# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"

# An cefwinhelper output that does nothing.
class LogStash::Outputs::Cefwinhelper < LogStash::Outputs::Base
  config_name "cefwinhelper"


  #concurrency :single
 
  default :codec, "json"
  
  config :host, :validate => :string, :required => true
  config :port, :validate => :number, :required => true
  config :reconnect_interval, :validate => :number, :default => 10

  
  class Client
    public
    def initialize(socket, logger)
      @socket = socket
      @logger = logger
      @queue  = Queue.new
    end

    public
    def run
      loop do
        begin
          @socket.write(@queue.pop)
        rescue => e
          @logger.warn("tcp output exception", :socket => @socket,
                       :exception => e)
          break
        end
      end
    end # def run

    public
    def write(msg)
      @queue.push(msg)
    end # def write
  end # class Client

  public
  def register
    require "socket"
    require "stud/try"
    client_socket = nil
    @codec.on_event do |event, payload|
      begin
        client_socket = connect unless client_socket
        r,w,e = IO.select([client_socket], [client_socket], [client_socket], nil)
        # don't expect any reads, but a readable socket might
        # mean the remote end closed, so read it and throw it away.
        # we'll get an EOFError if it happens.
        client_socket.sysread(16384) if r.any?

        # Now send the payload
        client_socket.syswrite(event.get('cef_output')) if w.any?
      rescue => e
        @logger.warn("tcp output exception", :host => @host, :port => @port,
                     :exception => e, :backtrace => e.backtrace)
        client_socket.close rescue nil
        client_socket = nil
        sleep @reconnect_interval
        retry
      end
    end
  end # def register


  private
  def connect
    Stud::try do
      client_socket = TCPSocket.new(@host, @port)
      client_socket.instance_eval { class << self; include ::LogStash::Util::SocketPeer end }
      @logger.debug("Opened connection", :client => "#{client_socket.peer}")
      return client_socket
    end
  end # def connect

 
  public
  def receive(event)

    # Map windows versions
    windowsVersion = event.get("WindowsVersion")
    if windowsVersion == "Windows Server 2012 R2"
       windowsKeyMapFamily = "Windows 2012 R2"
       windowsParserFamily = "Windows 2012 R2|2012|8"
    elsif windowsVersion == "Windows Server 2012"
       windowsKeyMapFamily = "Windows 2012"
       windowsParserFamily = "Windows 2012 R2|2012|8"
    elsif windowsVersion == "Windows 8"
       windowsKeyMapFamily = "Windows 8"
       windowsParserFamily = "Windows 2012 R2|2012|8"
    elsif windowsVersion == "Windows Server 2008 R2"
       windowsKeyMapFamily = "Windows Server 2008 R2"
       windowsParserFamily = "Windows 2008 R2|2008|7|Vista"
    elsif windowsVersion == "Windows Server 2008"
       windowsKeyMapFamily = "Windows Server 2008"
       windowsParserFamily = "Windows 2008 R2|2008|7|Vista"
    elsif windowsVersion == "Windows 7"
       windowsKeyMapFamily = "Windows 7"
       windowsParserFamily = "Windows 2008 R2|2008|7|Vista"
    elsif windowsVersion == "Windows Vista"
       windowsKeyMapFamily = "Windows Vista"
       windowsParserFamily = "Windows 2008 R2|2008|7|Vista"
    else
       windowsVersion = "Windows Server 2012 R2"
       windowsKeyMapFamily = "Windows 2012 R2"
       windowsParserFamily = "Windows 2012 R2|2012|8"
    end

    # Keyword extract from XML
    tmpSplitResults = event.get("RawXml").match(/.*\<Keywords\>(.*)\<\/Keywords\>.*/).to_a
    tmpField = tmpSplitResults[1]
    eventType = ""
    if tmpField == "0x8020000000000000"
       eventType = "Audit_success"
    elsif tmpField == "0x8010000000000000"
       eventType = "Audit_failure"
    end

    # Standard header
    cef_output = "EventlogType=#{event.get('Channel')}"
    cef_output = "#{cef_output}&&EventIndex=000000000&&WindowsVersion=#{windowsVersion}&&WindowsKeyMapFamily=#{windowsKeyMapFamily}&&WindowsParserFamily=#{windowsParserFamily}&&DetectTime=#{event.get('PreciseTimeStamp')}"

    # TODO: PreciseTimeStamp needs 2017-01-24T11:58:12.583Z to 2017-1-24 14:7:59
    cef_output = "#{cef_output}&&EventSource=#{event.get('ProviderName')}&&EventID=#{event.get('EventId')}&&EventType=#{eventType}&&EventCategory=#{event.get('Task')}&&User="

    # ComputerName extract from XML
    tmpSplitResults = event.get("RawXml").match(/.*\<Computer\>(.*)\<\/Computer\>.*/).to_a
    tmpField = tmpSplitResults[1]
    cef_output = "#{cef_output}&&ComputerName=#{tmpField}"

    # Split the double-LF to practically split SECTIONS
    tmpSplitResults = event.get("Description").gsub("\t","").gsub("\r","").split(/\n\n/)
    cef_output = "#{cef_output}&&Description=#{tmpSplitResults[0]}"
    # For every SECTION
    for elem in tmpSplitResults
      # Try to split SUBSECTIONS
      tmpSplitSubResults = elem.split(/\n/)
      # If first line of SUBSECTION is a header
      if tmpSplitSubResults[0].end_with?(":")
         tmpHeader = tmpSplitSubResults[0]
         tmpSplitSubResults = tmpSplitSubResults.drop(1)
         for subelem in tmpSplitSubResults
            kv = subelem.split(/:/,2)
            unless kv[1].nil?
              cef_output = "#{cef_output}&&#{tmpHeader}#{kv[0]}=#{kv[1]}"
            end
         end
      # If it is just one line with header plus value
      elsif tmpSplitSubResults[0].include? ":"
         kv = tmpSplitSubResults[0].split(/:/,2)
         unless kv[1].nil?
            cef_output = "#{cef_output}&&#{kv[0]}=#{kv[1]}"
         end
      end
    end

    # Add newline    
    cef_output = "#{cef_output}\r\n"

    # Add to the JSON the combined cef
    event.set("cef_output", cef_output)

    # Trigger the codec onEvent action
    @codec.encode(event)
  end # def receive

end # class LogStash::Outputs::Cefwinhelper
