# Example manual JWT Authentication

### File tree
- `auth_manual.js` - contains a manual generating and checking JWT token example
- `auth_with_lib.js` - contains generating JWT with `jsonwebtoken` library
- `test_bd.json` - example json, you can remove it and execute real BD get/set
- `server.js` - express server
- `.env` - contain environment variables:
    - `PORT`
    - `SECRET_KEY` - used in JWT generation
- `frontend`:
    - `index.html` - index page with login form
    - `private.html` - private page, you can enter here only if you are logged in
    - `style.css` - some styles

## Before run
Please download dependencies by

```
yarn install
```

### How to run
`yarn dev` - to develop with automatic restart
`yarn run` - to production run

## How to use
1. Go to `/`
2. Login with credentials in `test_bd.json`
3. Go to `/private-page` and check for `private-page` not redirect to `/`
4. Create test POST request to `/private-request` with    
`Authorization: Bearer ${your token from cookies}` and check response

> All algorithms are in the comments 
---
Danila, Stavrov