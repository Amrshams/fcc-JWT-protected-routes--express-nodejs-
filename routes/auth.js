import express from "express";
import { findByEmail, readUsers, writeUsers } from "../utils/db.js";
import bcrypt from "bcryptjs";
import { randomUUID } from "crypto"
import { signToken } from "../utils/jwt.js"
import authenticate from "../middleware/authenticate.js";
import { blacklistToken } from "../utils/token-blacklist.js"

const router = express.Router()

router.post("/register", async (req, res) => {

    try {
        const { email, password } = req.body
        if (!email || !password) {
           return res.status(400).send("Email and password are required")
        }

        if (findByEmail(email)) {
            return res.status(409).send("Email already in use")
        }

        const HASHED_PW = await bcrypt.hash(password, 10)

        //Read the existing data (readUsers())
        const users = readUsers()

        const newUser = {
            id: randomUUID(),
            email: email,
            passwordHash: HASHED_PW,
            role: "user"
        }

        //Modify the array in memory (Push the new user onto the array)
        users.push(newUser)

        //Save the updated data (persist it with writeUsers())
        writeUsers(users)

        const token = signToken({
            id: newUser.id,
            email: newUser.email,
            role: newUser.role
        })
        return res.status(201).json({ message: "User registered successfully", token })
    } catch (err) {
        res.status(500).json({ message: err.message})
    }

})


router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required" });
        }

        const user = findByEmail(email)

        if (!user) {
            return res.status(401).json({ message: "Invalid credentials" })
        }

        //bcrypt.compare(plainText, hash) returns a promise that 
        // resolves to true when they match

        const passwordMatch = await bcrypt.compare(password, user.passwordHash)
        if (!passwordMatch) {
            return res.status(401).json({ message: "Invalid credentials" })
        }
        const token = signToken({
            id: user.id,
            email: user.email,
            role: user.role
        })
        return res.json({ message: "Logged In", token })
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
})

router.get("/profile", authenticate, (req,res) => {
    res.json({ user: req.user })
})

router.post("/logout", authenticate, (req, res) => {
    const token = req.headers.authorization.split(" ")[1]
    blacklistToken(token)
    res.json({ message: "Logged out successfully" })
})


export default router;