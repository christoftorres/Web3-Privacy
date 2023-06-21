const nullLogFunc = () => { }
const actualLogFunc = console.log
const nullLogger = Object.freeze({
  debug: nullLogFunc,
  verbose: nullLogFunc
})
const debugLogger = Object.freeze({
  debug: actualLogFunc,
  verbose: nullLogFunc
})
const verboseLogger = Object.freeze({
  debug: actualLogFunc,
  verbose: actualLogFunc
})
const logLevelToLoggerMap = {
  none: nullLogger,
  debug: debugLogger,
  verbose: verboseLogger
}

const getLoggerForLevel = level => {
  return logLevelToLoggerMap[level]
}
const getLogger = args => {
  return getLoggerForLevel(args.debugLevel)
}

module.exports = {
  getLoggerForLevel,
  getLogger
}
