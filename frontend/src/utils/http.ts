import Axios from 'axios'
import {readBlobAsJSON} from './utils'
// Set config defaults when creating the axios
const apiUrl = import.meta.env.VITE_API_URL as string

const axios = Axios.create({
  baseURL: apiUrl,
  timeout: 20000,
})
console.log('apiUrl=', apiUrl)

axios.interceptors.request.use(
    (config) => {
      return config
    },
    (err) => {
      return Promise.reject(err)
    }
)

axios.interceptors.response.use(
    (res) => {
      // 为了更好的ts类型推断， 不返回res.data
      return res
    },
    async (e) => {
      // e的构成： const {config, request, response} = e;
      const res = e.response
      console.log('res.status=', res.status)

      if (res.status === 0) {
        // 网络不通或请求超时（没有响应）
        console.log(e.message)
        return Promise.reject({
          code: 'timeout',
          message: 'Request timed out. Please try again later.',
        })
      } else {
        // 请求返回4xx或5xx
        if (res.status === 401) {
          // 401: token过期，clear token and go to login page.
          // router.replace({
          //   name: 'Login',
          // })
        } else {
          // 处理文件下载出错的情况
          // read Blob (octet-stream) to JSON object
          let responseData = null
          console.log('res=', res)
          if (res.config.responseType === 'blob') {
            responseData = await readBlobAsJSON(res.data)
          } else {
            // 处理其他错误
            responseData = res.data
          }

          return Promise.reject(responseData)
        }
      }
    }
)

export default axios
