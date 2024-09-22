"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = __importDefault(require("zod"));
const client_1 = require("@prisma/client");
const bcrypt_1 = __importDefault(require("bcrypt"));
require('dotenv').config(); // Importing dotenv to load env variables
const app = (0, express_1.default)();
app.use(express_1.default.json());
const port = 3000;
const prisma = new client_1.PrismaClient(); // Initialize Prisma client
// JWT_SECRET 
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not defined in the environment variables");
}
// Home route
app.get("/", (req, res) => {
    res.send("This is the Home Page");
});
// Zod schema for signup data validation
const signupdata = zod_1.default.object({
    username: zod_1.default.string().min(3, 'Username must be at least 3 characters long'),
    password: zod_1.default.string().min(6, 'Password must be at least 6 characters long'),
    firstname: zod_1.default.string(),
    lastname: zod_1.default.string()
});
// Route to register a new user
app.post("/signup", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const parseResult = signupdata.safeParse(req.body);
    if (!parseResult.success) {
        return res.status(400).json({ message: "Invalid data entered. Please enter correct data" });
    }
    const { username, password, firstname, lastname } = parseResult.data;
    try {
        // Check if the user already exists
        const existingUser = yield prisma.user.findUnique({
            where: { username }
        });
        if (existingUser) {
            return res.status(400).json({ message: "Username is already taken" });
        }
        // Hash the password
        const hashedPassword = yield bcrypt_1.default.hash(password, 10);
        // Store the user in the database
        const newUser = yield prisma.user.create({
            data: {
                username,
                password: hashedPassword, // Store the hashed password
                firstname,
                lastname
            }
        });
        // Generate JWT token
        const token = jsonwebtoken_1.default.sign({ id: newUser.id, username, firstname, lastname }, JWT_SECRET, {
            expiresIn: '1h' // Set token expiration time
        });
        res.status(201).json({
            message: "User registered successfully",
            token
        });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ error: "An error occurred during registration" });
    }
}));
app.post("/login", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { username, password } = req.body;
    try {
        const user = yield prisma.user.findUnique({
            where: { username }
        });
        if (!user) {
            return res.status(400).json({ message: "Invalid username or password" });
        }
        const isPasswordValid = yield bcrypt_1.default.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: "Invalid username or password" });
        }
        const token = jsonwebtoken_1.default.sign({ id: user.id, username: user.username, firstname: user.firstname, lastname: user.lastname }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({
            message: "Login successful",
            token
        });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ error: "An error occurred during login" });
    }
}));
// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
