import axios from 'axios'

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

// Anti-CSRF token. The server binds it to the current session, so it is fetched
// lazily before the first write and dropped whenever the session changes.
let csrfToken = null

const SAFE_METHODS = ['get', 'head', 'options']
const SESSION_CHANGING = ['/auth/login', '/auth/register', '/auth/logout']

// Echo the token in the x-csrf-token header on every state-changing request.
// A forged cross-site form cannot set this header, which is what stops CSRF.
api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  if (SAFE_METHODS.includes(method)) return config

  if (!csrfToken) {
    const { data } = await api.get('/csrf-token')
    csrfToken = data.csrfToken
  }
  config.headers['x-csrf-token'] = csrfToken
  return config
})

api.interceptors.response.use(
  (res) => {
    if (SESSION_CHANGING.some(path => (res.config.url || '').includes(path))) csrfToken = null
    return res
  },
  (err) => {
    // A 403 can mean the token went stale (e.g. the session changed); refetch next time.
    if (err.response?.status === 403) csrfToken = null
    return Promise.reject(err)
  }
)
