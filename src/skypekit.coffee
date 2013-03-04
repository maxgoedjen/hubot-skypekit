{Robot, Adapter, TextMessage, EnterMessage, LeaveMessage, CatchAllMessage} = require "hubot"

class SkypeAdapter extends Adapter
  send: (user, strings...) ->
    console.log 'SEND'
    out = ""
    out = ("#{str}\n" for str in strings)
    json = JSON.stringify
      room: user.room
      message: out.join('')
    console.log json
    @skype.stdin.write json + '\n'

  reply: (user, strings...) ->
    console.log 'REPLY'
    @send user, strings...

  run: ->
    self = @
    stdin = process.openStdin()
    stdout = process.stdout
    pyScriptPath = __dirname+'/skypekit.py'
    py = 'python'
    @skype = require('child_process').spawn(py, [pyScriptPath])
    @skype.stdout.on 'data', (data) =>
        decoded = JSON.parse(data.toString())
        console.log decoded
        user = self.userForName decoded.user
        unless user?
            id = (new Date().getTime() / 1000).toString().replace('.','')
            user = self.userForId id
            user.name = decoded.user
        user.room = decoded.room
        return unless decoded.message
        console.log 'hit #{user}'
        self.receive new TextMessage (user, decoded.message)
    @skype.stderr.on 'data', (data) =>
        @robot.logger.error data.toString()
    @skype.on 'exit', (code) =>
        @robot.logger.error "Lost connection with Skype... Exiting"
        process.nextTick -> process.exit(1)
    @skype.on "uncaughtException", (err) =>
      @robot.logger.error "#{err}"

    process.on "uncaughtException", (err) =>
      @robot.logger.error "#{err}"

    @emit "connected"

exports.use = (robot) ->
  new SkypeAdapter robot
