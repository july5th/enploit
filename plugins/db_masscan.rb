###
#
# Metasploit插件， 整合masscan，先使用masscan做大范围扫描，再用nmap确认服务及版本
# 例: 
#   load db_masscan
#   db_masscan -p8080 118.1.1.1/8 --nmap-version
#
# 运行前请确认普通用户有运行masscan的权限，设置命令如下:
#   chown root $(which masscan)
#   chmod u+s $(which masscan)
#
###

module Msf

class Plugin::DB_Masscan < Msf::Plugin

  ###
  #
  # This class implements a sample console command dispatcher.
  #
  ###
  class ConsoleCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    attr_accessor :nmap, :queue, :end_str, :nmap_timeout

    #
    # The dispatcher's name.
    #
    def name
      "DB_Masscan"
    end

    #
    # Returns the hash of commands supported by this dispatcher.
    #
    def commands
      {
        "db_masscan" => "Scan port using masscan.", 
        "db_masscan_help" => "Help about db_masscan."
      }
    end

    #
    # This method handles the db_masscan command.
    #
    def cmd_db_masscan(*args)
      self.queue = Queue.new
      self.end_str = "END"
      self.nmap_timeout = 120
      max_nmap_thread_number = 32

      ::ActiveRecord::Base.connection_pool.with_connection {
        masscan = Rex::FileUtils.find_full_path("masscan")
        if (not masscan)
          print_error("The masscan executable could not be found")
          return
        end

        if (args.length == 0)
          cmd_db_masscan_help
          return
        end

        nmap_version = false
        arguments = []
        while (arg = args.shift)
          case arg
          when '--nmap-version'
            nmap_version = true
          when '--help', '-h'
            cmd_db_masscan_help
            return
          else
            arguments << arg
          end
        end
         
        self.nmap = Rex::FileUtils.find_full_path("nmap")
        if (nmap_version and not self.nmap)
          print_error("The nmap executable could not be found, so do not use --nmap-version.")
          return
        end

        begin
          masscan_pipe = ::Open3::popen3(masscan, *arguments)
          temp_masscan_threads = []
          temp_nmap_threads = []
          1.upto(max_nmap_thread_number) do |i|
            temp_nmap_threads << framework.threads.spawn("masscan-nmap-#{i}", false) do 
              nmap_scan_thread 
            end
          end
          temp_masscan_threads << framework.threads.spawn("db_masscan-Stdout", false, masscan_pipe[1]) do |np_1|
            np_1.each_line do |masscan_out|
              next if masscan_out.strip.empty?
              output = masscan_out.strip
              print_status("Masscan: #{output}")
              if output =~ /Discovered open port (\d+)\/(tcp|udp) on ([\d|\.]*)/
                port = $1
                prot = $2
                ip = $3
                if nmap_version
                  self.queue.push([ip, port, prot])
                else
                  print_status("Masscan: import #{ip} #{port}/#{prot}")
                end
              end
            end
          end

          temp_masscan_threads << framework.threads.spawn("db_masscan-Stderr", false, masscan_pipe[2]) do |np_2|
            np_2.each_line do |masscan_err|
              next if masscan_err.strip.empty?
              print_status("Masscan: '#{masscan_err.strip}'")
            end
          end

          temp_masscan_threads.map {|t| t.join rescue nil}
          masscan_pipe.each {|p| p.close rescue nil}
          1.upto(max_nmap_thread_number * 2) do |i|
            self.queue.push self.end_str
          end
          temp_nmap_threads.map {|t| t.join rescue nil}
        rescue ::IOError
        end

      }

    end

    #
    # This method handles the db_masscan_help command.
    #
    def cmd_db_masscan_help
      masscan = Rex::FileUtils.find_full_path('masscan') ||
      if (not masscan)
        print_error("The masscan executable could not be found")
        return
      end
      stdout, stderr = Open3.capture3([masscan, 'masscan'], '--help')
      print_status("db_masscan [--nmap-version] args")
      print_status("")
      stdout.each_line do |out_line|
        next if out_line.strip.empty?
        print_status(out_line.strip)
      end
      stderr.each_line do |err_line|
        next if err_line.strip.empty?
        print_error(err_line.strip)
      end
    end

    def nmap_scan_thread
      while (task = self.queue.pop)
        return nil if task == self.end_str
        ip = task[0]
        port = task[1].to_i
        prot = task[2]
        fd = Rex::Quickfile.new(["plugin-db-masscan-nmap-#{ip}-#{prot}-#{port}-", '.xml'], Msf::Config.local_directory)
        begin 
          arguments = ['-P0', '--open']
          case prot
          when 'tcp'
            arguments.push '-sV'
          when 'udp'
            arguments.push '-sUV'
          end
          arguments.push "-p#{port}"
          arguments.push ip
          arguments.push('-oX', fd.path)
          arguments.push('--host-timeout', self.nmap_timeout)
          
          print_status("Masscan: start nmap for #{ip} #{port}/#{prot}")

          command = "#{self.nmap} #{arguments.join(' ')}"
          output = `#{command}`
          output.each_line do |x|
            print_status("Nmap: #{x.strip}") if x.strip =~ /open/
          end

          framework.db.import_nmap_xml_file(:filename => fd.path)
          print_status("Saved XML results #{fd.path}") 
        ensure
          fd.close
          fd.unlink 
        end
      end
    end

  end

  #
  # The constructor is called when an instance of the plugin is created.  The
  # framework instance that the plugin is being associated with is passed in
  # the framework parameter.  Plugins should call the parent constructor when
  # inheriting from Msf::Plugin to ensure that the framework attribute on
  # their instance gets set.
  #
  def initialize(framework, opts)
    super

    # If this plugin is being loaded in the context of a console application
    # that uses the framework's console user interface driver, register
    # console dispatcher commands.
    add_console_dispatcher(ConsoleCommandDispatcher)

    print_status("DB Masscan plugin loaded.")
  end

  #
  # The cleanup routine for plugins gives them a chance to undo any actions
  # they may have done to the framework.  For instance, if a console
  # dispatcher was added, then it should be removed in the cleanup routine.
  #
  def cleanup
    # If we had previously registered a console dispatcher with the console,
    # deregister it now.
    remove_console_dispatcher('DB_Masscan')
  end

  #
  # This method returns a short, friendly name for the plugin.
  #
  def name
    "db_masscan"
  end

  #
  # This method returns a brief description of the plugin.  It should be no
  # more than 60 characters, but there are no hard limits.
  #
  def desc
    "Using Masscan to scan port."
  end

protected
end

end
