const express = require('express');
const jwt = require('jsonwebtoken');
const pg = require('pg')
const bcrypt = require('bcryptjs')

const server = express();
const port = 3001;

server.use(express.json()); //Paso 4.


server.listen(port, ()=>{
    console.log(`Listening on port http://localhost:${port}`);
});

//Paso 5
const pool = new pg.Pool({
    user: "postgres",
    host: "localhost",
    database: "usuarios",
    password: "12345",
    port: 5432
})


server.post('/singup', async(req, res) => {
    const {email, password} = req.body;
    try {
        const emailExist = await pool.query(
            "SELECT * FROM users WHERE email = $1",
            [email]

            );
        if(emailExist.rows.length > 0){
            throw new Error(`Ya existe este email`)
        } else {
            //Hasheamos la password
            const hashPassword = await bcrypt.hash(password, 10);

            const newUser = await pool.query(
                "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id",
                [email, hashPassword]
            );

            //Generamos el token
            const userId = newUser.rows[0].id //extraemos el id
            const token = jwt.sign({userId}, 'jwt_secret_code')

            res.status(200).json({token})
        }
    } catch (error) {
        res.status(400).json({error: error.message})
    }
});

server.post('/login', async(req, res) => {
    const {email, password} = req.body;

    try {
        const findUser = await pool.query(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );

        if(findUser.rows.length === 0){
            throw new Error('El email no existe')
        };

        const compareHashPassword = await bcrypt.compare(password, findUser.rows[0].password);

        if(!compareHashPassword){
            throw new Error('Contraseña inválida')
        };

        const token = jwt.sign({userId: findUser.rows[0].id}, 'jwt_secret_code')
        
        res.status(200).json({token})
    } catch (error) {
        res.status(400).json({error: error.message});
    };
});

server.get('/verificacion', async(req, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    try {
        if(!token) {
            throw new Error('Token incorrecto')
        }
        const verifyToken = await jwt.verify(token, 'jwt_secret_code')
        req.userId = verifyToken.userId
        res.status(200).json(verifyToken)
    } catch (error) {
        res.status(400).json({error: error.message})
    }
});

module.exports = server