import { fileURLToPath } from 'url'
import path from 'path'
import fs from 'node:fs/promises'

function collectRequestData(request) {
  return new Promise((resolve) => {
    const data = []

    request.on('data', (chunk) => {
      data.push(chunk)
    })

    request.on('end', () => {
      const dataStr = Buffer.concat(data).toString()
      resolve(dataStr)
    })
  })
}

function sendResponse(response, statusCode = 200, headers, data) {
  response.writeHead(statusCode, headers)
  response.end(data)
}

function convertNotificationForTracking(notification) {
  if (notification && notification.NotificationRequestItem) {
    const notificationRequestItem = notification.NotificationRequestItem
    return {
      eventCode: notificationRequestItem.eventCode,
      eventDate: notificationRequestItem.eventDate,
      pspReference: notificationRequestItem.pspReference,
      success: notificationRequestItem.success,
    }
  }
  return notification
}

function getNotificationForTracking(notification) {
  if (notification && Array.isArray(notification)) {
    const notificationListForTracking = []
    notification.forEach((notificationElement) => {
      notificationListForTracking.push(
        convertNotificationForTracking(notificationElement),
      )
    })
    return notificationListForTracking
  }
  return convertNotificationForTracking(notification)
}

async function readAndParseJsonFile(pathToJsonFileFromProjectRoot) {
  const currentFilePath = fileURLToPath(import.meta.url)
  const currentDirPath = path.dirname(currentFilePath)
  const projectRoot = path.resolve(currentDirPath, '../..')
  const pathToFile = path.resolve(projectRoot, pathToJsonFileFromProjectRoot)
  const fileContent = await fs.readFile(pathToFile)
  return JSON.parse(fileContent)
}

// Event codes from Adyen webhooks that are NOT HMAC-signed (e.g. the Generic Pending
// webhook, eventCode PENDING) and that carry no transaction, so they may be
// authenticated with Basic Auth instead of HMAC. Only add a code here when it is both
// (1) confirmed unsigned by Adyen for the webhook in use and (2) non-money
// (transactionType null in resources/adyen-events.json).
const UNSIGNED_EVENT_CODES = new Set(['PENDING'])

export { UNSIGNED_EVENT_CODES }

export default {
  collectRequestData,
  sendResponse,
  getNotificationForTracking,
  readAndParseJsonFile,
}
