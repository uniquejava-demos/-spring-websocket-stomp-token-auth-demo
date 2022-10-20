import {useEffect, useState} from 'react'
import http from '../utils/http'

function Login({client, setClient, setConnected, authenticated, setAuthenticated}) {
  const [message, setMessage] = useState('')

  useEffect(() => {
    console.log('useEffect ..')
    const token = sessionStorage.getItem("access_token");
    if (token) {
      console.log('token: ' + token)
      setAuthenticated(true)
    } else {
      console.log('unauthenticated')
    }
  }, [])

  async function onLogin() {
    const res = await http.post('http://localhost:8080/token', null, {
      auth: {
        username: 'cyper',
        password: '123456'
      },
    })
    setAuthenticated(res.data.code === 'success')
    setMessage(res.data.message)
    sessionStorage.setItem("access_token", res.data.data);
  }

  async function onWhoami() {
    const res = await http.get('/whoami')
    setMessage(res.data.message)
  }

  async function onLogout() {
    await http.post('/logout?access_token' + sessionStorage.getItem("access_token"))
    sessionStorage.clear();
    setAuthenticated(false)

    await client.deactivate();

    setClient(null)

    setConnected(false)
  }

  return (
      <>
        {authenticated ? (
            <div>
              <button onClick={onWhoami}>Who am I?</button>
              <button onClick={onLogout}>Logout</button>
            </div>
        ) : (
            <button onClick={onLogin}>Login</button>
        )}
        <div>Authenticated? {authenticated ? 'true' : 'false'} </div>
        <div>
          Message: <code>{message}</code>
        </div>
      </>
  )
}

export default Login
