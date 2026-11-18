import jwt from "jsonwebtoken";

//returns a signed token. 
export function signToken(payload) {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1d"})
}


//returns the decoded payload if the token is valid, 
// but throws if the token is invalid or expired
export function verifyToken(token) {
    try{
       return jwt.verify(token, process.env.JWT_SECRET)

    } catch {
        return null
    }
}