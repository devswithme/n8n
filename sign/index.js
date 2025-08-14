import express from 'express'
import crypto from 'crypto'
import dotenv from 'dotenv'

dotenv.config()
const app = express()
app.use(express.json())

function verifyKey(req, res, next) {
    const authHeader = req.headers["authorization"];
    const apiKey = authHeader?.split(" ")[1];

    if (apiKey === process.env.API_KEY) {
        return next();
    } else {
        return res.status(401).json({ success: false, data: "Unauthorized" });
    }
}


app.post("/create", verifyKey, (req, res) => {
    try {
        const { merchant_ref, amount } = req.body;
        const privateKey = process.env.PRIVATE_KEY;
        const merchant_code = process.env.MERCHANT_CODE;

        const signature = crypto
            .createHmac("sha256", privateKey)
            .update(`${merchant_code}${merchant_ref}${amount}`)
            .digest("hex");

        return res.json({ success: true, data: signature });
    } catch (err) {
        return res.status(500).json({ success: false, data: err.message });
    }
});


app.post("/verify", verifyKey, (req, res) => {
    try {
        const { body, signature } = req.body;
        const privateKey = process.env.PRIVATE_KEY;

        const hmac = crypto
            .createHmac("sha256", privateKey)
            .update(JSON.stringify(body))
            .digest("hex");

        return res.json({
            success: true,
            data: hmac === signature
        });
    } catch (err) {
        return res.status(500).json({ success: false, data: err.message });
    }
});


app.listen(3001)
