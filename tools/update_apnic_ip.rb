require 'pathname'

class UpdateIP
  def initialize
    @url = 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
    @data_dir = File.join(Pathname.new(__FILE__).parent.parent.realpath, 'data/ip')
    Dir.mkdir @data_dir unless File.exists?(@data_dir)
    @data_file = File.join(@data_dir, 'all')
  end

  def update
    if not File.exists?(@data_file) or get_file_date_str != Time.now.strftime('%Y%m%d')
      get_ip_file
    end
    
    c = update_county_ip 'CN'
    print "Update end, all count: #{c}\n"
  end

  def get_ip_file
    command = "wget #{@url} -O #{@data_file}"
    print "run command: #{command}\n"
    `#{command}`
  end

  def get_file_date_str
    File.open(@data_file).each_line do |line|
      next if line[0] == '#'
      line_list = line.split('|')
      return line_list[2]
    end
  end

  def update_county_ip country
    all_count = 0
    country_file = File.join(@data_dir, "#{country.downcase}_ip")
    File.unlink(country_file) if File.exists?(country_file)
    fp = File.open(country_file, 'a+')
    begin
      File.open(@data_file).each_line do |line|
        next if line[0] == '#'
        line_list = line.chomp.split('|')
        next if line_list[0] != 'apnic' or line_list[1] != 'CN' or line_list[2] != 'ipv4'
        c = line_list[4].to_i
        all_count += c
        net_mask = (32 - Math.log2(c)).to_i
        fp.write("#{line_list[3]}/#{net_mask}\n")
        fp.flush
      end
    ensure
      fp.close
    end
    return all_count
  end

end

UpdateIP.new.update
