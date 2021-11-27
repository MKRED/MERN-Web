const {Router} = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

// /api/auth/register
router.post(
    '/register', 
    [
        check( 'login', 'Min 3').isLength({min: 3}),
        check( 'password', 'Min 6').isLength({min: 6})
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Error data'
            })
        }

        const {login, password} = req.body

        const candidate = await User.findOne({ login })

        if (candidate) {
            return res.status(400).json({ messege: 'Err User already exits' })
        }

        const hashedPassword = await bcrypt.hash(password, 12)
        const user = new User({ login, password: hashedPassword })

        await user.save()

        res. status(201).json({ messege: 'User created' })

    } catch (e) {
        res.status(500).json({message: 'Register Error'})
    }
})

// /api/auth/login
router.post(
    '/login', 
    [
        check( 'login', 'Min 3 in login').isLength({min: 3}),
        check( 'password', 'Min 6 in login').isLength({min: 6}).exists()
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)

        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Error data in login'
            })
        }

        const {login, password} = req.body

        const user = await User.findOne({ login })

        if(!user) {
            return res.status(400).json({ message: 'User not find' })
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if(!isMatch) {
            return res.status(400).json({ message: 'Pass Error' })
        }

        const token = jwt.sign(
            { userId: user.id },
            config.get('jwtSecret'),
            { expiresIn: '1h' }
        )

        res.json({ token, userId: user.id })

    } catch (e) {
        res.status(500).json({message: 'Register Error'})
    }
})

module.exports = router