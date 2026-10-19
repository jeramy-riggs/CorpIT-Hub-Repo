const { createLogger, format, transports } = require('winston');
const path = require('path');

const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.errors({ stack: true }),
    format.printf(({ timestamp, level, message, stack }) =>
      `${timestamp} [${level.toUpperCase()}] ${stack || message}`
    )
  ),
  transports: [
    new transports.Console({ format: format.colorize({ all: true }) }),
    new transports.File({
      filename: path.join(__dirname, '..', '..', 'logs', 'app.log'),
      maxsize: 5_242_880, // 5 MB
      maxFiles: 5,
    }),
    new transports.File({
      filename: path.join(__dirname, '..', '..', 'logs', 'error.log'),
      level: 'error',
      maxsize: 5_242_880,
      maxFiles: 5,
    }),
  ],
});

module.exports = logger;
