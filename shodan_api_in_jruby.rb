#!/usr/bin/env ruby

require "java"
require "json"
require "thread"
require "socket"
require "net/http"
require "uri"

java_import 'burp.IBurpExtender'
java_import 'burp.IBurpExtenderCallbacks'
java_import 'burp.IExtensionHelpers'
java_import 'burp.IContextMenuFactory'
java_import 'burp.IContextMenuInvocation'

import javax.swing.JMenuItem

# import urllib2

class BurpExtender
  include IBurpExtender
  include IContextMenuFactory

  attr_reader :callbacks

  def registerExtenderCallbacks(callbacks)
        @callbacks = callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Shodan Scan")
        callbacks.registerContextMenuFactory(self)
  end

  def createMenuItems(invocation)
    menu_list = []
    menu = JMenuItem.new "Scan with Shodan", nil
    menu.addActionListener do |e|
      startThreaded(invocation)
    end
    menu_list << menu
    menu_list
  end

  def start_scan(invocation)
    http_traffic = invocation.getSelectedMessages()
    if http_traffic.length !=0
        service = http_traffic[0].getHttpService()
        hostname = service.getHost()
        ip = IPSocket.getaddress(hostname)
        uri = URI.parse("https://api.shodan.io/shodan/host/#{ip}?key=1lgyO39gi4FOQqI7Y2TYndvNUJNRGjYe")
        req = Net::HTTP.get_response(uri)
        response = JSON.parse(req.body)
        puts "This report is last updated on  #{response['last_update']}"
        puts "IP - #{response['ip_str']}"
        puts "ISP - #{response['isp']}"
        puts "City - #{response['city']}"
        puts "Possible Vulns - #{response['vulns']}"
        puts "Open Ports -  #{response['ports']}"
    end
  end

  def startThreaded(args)
    Thread.new{start_scan(args)}
  end
end
