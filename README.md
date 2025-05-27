# svc-lib-webpush

A custom service library for web push notifications. Utilizes the [web push api](https://developer.mozilla.org/en-US/docs/Web/API/Push_API) protocol to send notifications to users devices using VAPID keys for authentication. This library is designed to be lightweight and easy to integrate into Node.js applications.

## Installation

```bash
npm install git+https://github.com/tetherto/svc-lib-webpush.git
```

## Features

- Pure Node.js implementation for sending web push notifications
- VAPID key management
- Subscription validation helpers
- Error handling for expired or invalid subscriptions
- No external dependencies

## Limitations
- Currently only aes128gcm encryption is supported
- FCM and GCM push notification implementation is pending

## Usage

### Basic Usage

```javascript
const WebPushService = require('svc-lib-webpush')

// Create service instance with VAPID credentials
const pushService = new WebPushService({
  vapid: {
    subject: 'mailto:contact@example.com',
    publicKey: 'YOUR_PUBLIC_KEY',
    privateKey: 'YOUR_PRIVATE_KEY'
  },
  logger: customLogger // optional
})

// Send notification to a subscription
const subscription = {
  endpoint: 'https://endpoint.example.com',
  keys: {
    p256dh: 'user_public_key',
    auth: 'user_auth_token'
  }
}

const payload = {
  title: 'New Notification',
  body: 'Hello world!',
  data: {
    url: 'https://example.com/details'
  }
}

try {
  const result = await pushService.sendNotification(subscription, payload)
  console.log('Notification sent:', result)
} catch (err) {
  console.error('Failed to send notification:', err)
}
```

### Generating VAPID Keys

If you need to generate new VAPID keys:

```javascript
const WebPushService = require('svc-lib-webpush')

// Generate new VAPID keys using static method
const keys = WebPushService.generateVapidKeys()
console.log('New VAPID keys:', keys)
// { publicKey: '...', privateKey: '...' }
```

## API Reference

### Constructor

```javascript
const service = new WebPushService(options)
```

Options:
- `vapid` (Object, required): VAPID credentials
  - `subject` (String, required): A mailto: URL or website URL
  - `publicKey` (String, required): VAPID public key
  - `privateKey` (String, required): VAPID private key
- `logger` (Object, optional): A logger with info and error methods

### Methods

#### `sendNotification(subscription, payload, options)`

Sends a push notification to a subscription.

- `subscription` (Object): PushSubscription object with endpoint and keys
- `payload` (Object|String): Notification data to send
- `options` (Object, optional): Additional options
  - `TTL` (Number): Time to live in seconds (default: 14400)
  - `urgency` (String): Notification urgency ('very-low', 'low', 'normal', 'high')

Returns a Promise that resolves to a result object:
```javascript
{
  success: true,
  statusCode: 200,
  body: '...'
}
```

#### `static generateVapidKeys()`

Static method that generates new VAPID keys.

Returns an object with:
```javascript
{
  publicKey: '...',
  privateKey: '...'
}
```

## License

Apache-2.0