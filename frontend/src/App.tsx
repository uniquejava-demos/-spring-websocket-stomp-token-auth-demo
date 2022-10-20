import {useState} from 'react'
import {Client} from '@stomp/stompjs'
import Login from './components/Login'

function App() {
  const [authenticated, setAuthenticated] = useState(false)
  const [connected, setConnected] = useState(false)
  const [client, setClient] = useState<null | Client>(null)
  const [messageInput, setMessageInput] = useState<string>('')

  function onConnect() {
    const token = sessionStorage.getItem("access_token");
    if (client === null && token !== null) {
      const client = new Client({
        brokerURL: `ws://localhost:8080/stomp`,

        // https://docs.spring.io/spring-framework/docs/4.3.x/spring-framework-reference/html/websocket.html#websocket-stomp-handle-broker-relay-configure
        // The STOMP broker relay always sets the login and passcode headers on every CONNECT frame that it forwards to the broker on behalf of clients.
        // Therefore WebSocket clients need not set those headers; they will be ignored.
        connectHeaders: {
          // login: 'user',
          // passcode: 'password',
          "access_token": token
        },
        debug: function (str) {
          console.log(str)
        },
        reconnectDelay: 5000,
        heartbeatIncoming: 4000,
        heartbeatOutgoing: 4000,
      })

      client.onConnect = function (frame) {
        // Do something, all subscribes must be done is this callback
        // This is needed because this will be executed after a (re)connect
        setConnected(true)
      }

      client.onDisconnect = function () {
        console.log('Client disconnected.')
        setConnected(false)
      }

      client.onWebSocketClose = function (evt) {
        console.log('WebSocket closed.')
        console.log(evt)
      }

      client.onStompError = function (frame) {
        // Will be invoked in case of error encountered at Broker
        // Bad login/passcode typically will cause an error
        // Complaint brokers will set `message` header with a brief message. Body may contain details.
        // Compliant brokers will terminate the connection after any error
        console.log('Broker reported error: ' + frame.headers['message'])
        console.log('Additional details: ' + frame.body)
      }

      setClient(client)
      client?.activate();
    } else {
      client?.activate();

    }
  }

  function onDisconnect() {
    client?.deactivate()
  }

  function onSend() {
    if (messageInput) {
      client?.publish({
        destination: '/app/class403',
        body: messageInput,
      })
      setMessageInput('')
    }
  }

  return (
      <>
        <h1> websocket demo</h1>
        <Login client={client} setClient={setClient} setConnected={setConnected} authenticated={authenticated}
               setAuthenticated={setAuthenticated}/>

        <hr/>

        {authenticated && <div>
          {connected ? (
              <div>
                <input
                    onChange={(event) => {
                      setMessageInput(event.target.value)
                    }}
                    value={messageInput}
                />
                <>
                  <button onClick={onSend} disabled={!messageInput}>
                    send
                  </button>
                  <button onClick={onDisconnect}>disconnect</button>
                </>
              </div>
          ) : (
              <button onClick={() => onConnect()}>Connect to Chat server</button>
          )}
        </div>}
      </>
  )
}

export default App
