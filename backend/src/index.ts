import express, { Request, Response } from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import zod from 'zod';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
require('dotenv').config(); // Importing dotenv to load env variables

const app = express();
app.use(express.json());

const port: number = 3000;
const prisma = new PrismaClient(); // Initialize Prisma client

// JWT_SECRET 
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined in the environment variables");
}

// Home route
app.get("/", (req: Request, res: Response) => {
    res.send("This is the Home Page");
});

// signup data validation
const signupdata = zod.object({
    username: zod.string().min(3, 'Username must be at least 3 characters long'),
    password: zod.string().min(6, 'Password must be at least 6 characters long'),
    firstname: zod.string(),
    lastname: zod.string()
});

// Route to Signup
app.post("/signup", async (req: Request, res: Response) => {
    const parseResult = signupdata.safeParse(req.body);

    if (!parseResult.success) {
        return res.status(400).json({ message: "Invalid data entered. Please enter correct data" });
    }

    const { username, password, firstname, lastname } = parseResult.data;

    try {
        // Check if the user already exists
        const existingUser = await prisma.user.findUnique({
            where: { username }
        });

        if (existingUser) {
            return res.status(400).json({ message: "Username is already taken" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Store the user in the DB
        const newUser = await prisma.user.create({
            data: {
                username,
                password: hashedPassword, 
                firstname,
                lastname
            }
        });

        //token generation
        const token = jwt.sign({ id: newUser.id, username, firstname, lastname }, JWT_SECRET, {
            expiresIn: '1h' // Set token expiration time
        });

        res.status(201).json({
            message: "User registered successfully",
            token
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "An error occurred during registration" });
    }
});

// Route to Login
app.post("/login", async (req: Request, res: Response) => {
    const { username, password } = req.body;

    try {
        const user = await prisma.user.findUnique({
            where: { username }
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid username or password" });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({ message: "Invalid username or password" });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, firstname: user.firstname, lastname: user.lastname },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: "Login successful",
            token
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "An error occurred during login" });
    }
});


// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
