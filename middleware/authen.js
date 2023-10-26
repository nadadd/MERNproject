import user from '../models/user';
import jwt from 'jsonwebtoken'
import asyncHandler from 'express-async-handler'


const protect = asyncHandler(async (req, res, next) => {
  let token

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    try {
      token = req.headers.authorization.split(' ')[1]
      const decoded = jwt.verify(token, process.env.JWT_SECRET)

      req.user = await user.findById(decoded.id).select('-password')

      next()
    } catch (err) {
      console.error(err)
      res.status(401)
      throw new Error('unauthorized')
    }
  }

  if (!token) {
    res.status(401)
    throw new Error('unauthorized')
  }
})

const isAdmin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next()
  } else {
    res.status(401)
    throw new Error('אין הרשאה. נדרשת הרשאת מנהל מערכת')
  }
}

export { protect, isAdmin }
