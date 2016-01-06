local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[ Find open .svn directories ]]
portrule = shortport.http

---
-- @usage
-- nmap --script http-dvcs -p 80,81,443,8080,8081 host
--
-- @output
-- 80/tcp open  http
-- | http-dvcs: 
-- |_  Entries: .svn/entries available


author = '@stoep'
license = 'See http://nmap.org/svn/docs/licenses/BSD-simplified'

action = function( host, port )
    local result    = stdnse.output_table()
    local found     = 0
    local uri
    local response
    
    local scan_git  = stdnse.get_script_args('git') or 0
    local scan_svn  = stdnse.get_script_args('svn') or 0
    local scan_hg   = stdnse.get_script_args('hg')  or 0 
    local scan_bzr  = stdnse.get_script_args('bzr') or 0
    
    -- if no arguments are given then all should be checked
    if scan_git == 0 and scan_svn == 0 and scan_hg == 0 and scan_bzr == 0 then
        scan_git = 1
        scan_svn = 1
        scan_hg  = 1 
        scan_bzr = 1
    end

    -- check .svn
    if scan_svn == 1 then
        uri      = '/.svn/entries'
        response = http.get( host, port, uri )
        
        if (response['status-line'] and response['status-line']:match('200%s+OK') and response['body']) then
            -- match if document contains has-props
            if string.match(response['body'], 'has%-props') then
                result['SVN'] = '.svn/entries available'
                found = found + 1 
            end
        end
    end 

    -- check .bzr
    if scan_bzr == 1 then
        uri      = '/.bzr/README'
        response = http.get( host, port, uri )
   
        if (response['status-line'] and response['status-line']:match('200%s+OK') and response['body']) then
            if string.match(response['body'], 'Bazaar') then
                result['Bazaar'] = '.bzr/README available'
                found = found + 1 
            end
        end
    end 

    -- check .hg
    if scan_hg == 1 then
        uri      = '/.hg/00changelog.i'
        response = http.get( host, port, uri )
  
        if (response['status-line'] and response['status-line']:match('200%s+OK') and response['body']) then
            if string.match(response['body'], 'dummy changelog') then
                result['Mercurial'] = '.hg/00changelog.i available'
                found = found + 1 
            end
        end
    end 

    -- check .git
    if scan_git == 1 then
        uri      = '/.git/HEAD'
        response = http.get(host,port,uri)
      
        if (response['status-line'] and response['status-line']:match('200%s+OK') and response['body']) then
            if string.match(response['body'], 'refs%/') then
                result['Git'] = '.git/HEAD available'
                found = found + 1 
            end
        end
    end 
  
    if found == 0 then 
        return nil
    else  
        return result
    end
end
