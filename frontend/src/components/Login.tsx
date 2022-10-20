import {useEffect, useState} from 'react'
import http from '../utils/http'

function Login() {
  const [authenticated, setAuthenticated] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    // 判断是否登录过了(XSRF-TOKEN)
    // JSESSIONID是 HttpOnly cookie， 无法通过js读到，所以读csrf token。
    console.log('useEffect ..')
    const cookieValue = document.cookie
        .split('; ')
        .find((row) => row.startsWith('XSRF-TOKEN='))
        ?.split('=')[1]
    if (cookieValue) {
      console.log('XSRF-TOKEN: ' + cookieValue)
      setAuthenticated(true)
    } else {
      console.log(document.cookie)
    }
  }, [])

  async function onLogin() {
    const params = new URLSearchParams()
    params.append('username', 'cyper')
    params.append('password', 'password')

    const res = await http.post('http://localhost:8080/login', params)
    setAuthenticated(res.data.code === 'success')
    setMessage(res.data.message)
  }

  async function onWhoami() {
    const res = await http.get('/whoami')
    setMessage(res.data.message)
  }

  async function onLogout() {
    await http.post('/logout')
    setAuthenticated(false)
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
