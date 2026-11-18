
const blacklist = new Set()


export function blacklistToken(token){
    return blacklist.add(token)
}


//this function return true if token is blacklisted and false if not
export function isBlacklisted(token) {
    return blacklist.has(token) 
}