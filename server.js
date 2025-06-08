require('dotenv').config(); // CARREGA AS VARIÁVEIS DE AMBIENTE DO ARQUIVO .ENV

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Necessário para gerar códigos aleatórios

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: 'http://127.0.0.1:5500', // Ou o endereço do seu frontend (ex: http://localhost:5500)
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true // Importante para permitir cookies/credenciais se você for usá-los (não estamos usando JWT com cookies aqui, mas é uma boa prática)
}));
app.use(express.json()); // Permite que o Express parseie JSON no corpo das requisições

// Conexão com o MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Conectado ao MongoDB Atlas'))
    .catch(err => console.error('Erro ao conectar ao MongoDB:', err));

// Esquema e Modelo do Usuário
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    verificationCode: { type: String }, // Campo para armazenar o código de verificação
    isVerified: { type: Boolean, default: false }, // Campo para indicar se o e-mail foi verificado
    codeExpires: { type: Date } // Data de expiração do código
});

// Hash da senha antes de salvar
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

const User = mongoose.model('User', userSchema);

// Configuração do Nodemailer
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_SECURE === 'true', // Use true para 465, false para 587 (TLS)
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Função para gerar um código de 6 dígitos
const generateVerificationCode = () => {
    return crypto.randomBytes(3).toString('hex').toUpperCase(); // Gera 6 caracteres hexadecimais
};

// ROTA DE CADASTRO
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // Verifica se o usuário já existe
        let user = await User.findOne({ email });
        if (user) {
            // Se o usuário existe mas não está verificado, podemos reenviar o código ou pedir para ele confirmar
            if (!user.isVerified) {
                const newCode = generateVerificationCode();
                user.verificationCode = newCode;
                user.codeExpires = new Date(Date.now() + 3600000); // Código expira em 1 hora
                await user.save();

                const mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: email,
                    subject: 'Confirme Seu E-mail - Silva Shop',
                    html: `
                        <p>Olá ${name},</p>
                        <p>Obrigado por se cadastrar na Silva Shop! Por favor, use o código abaixo para verificar seu e-mail e ativar sua conta:</p>
                        <h3>Seu Código de Verificação: <strong>${newCode}</strong></h3>
                        <p>Este código é válido por 1 hora.</p>
                        <p>Se você não solicitou este cadastro, por favor, ignore este e-mail.</p>
                        <p>Atenciosamente,<br>Equipe Silva Shop</p>
                    `
                };

                await transporter.sendMail(mailOptions);
                return res.status(200).json({ message: 'Você já tem uma conta, mas não verificada. Um novo código de verificação foi enviado para seu e-mail.' });
            } else {
                return res.status(400).json({ message: 'E-mail já cadastrado e verificado. Por favor, faça login.' });
            }
        }

        // Cria um novo usuário
        const verificationCode = generateVerificationCode();
        user = new User({
            name,
            email,
            password,
            verificationCode: verificationCode,
            codeExpires: new Date(Date.now() + 3600000) // Código expira em 1 hora
        });

        await user.save();
        console.log('Novo usuário registrado (não verificado) no DB:', user.email);

        // Envia e-mail de verificação
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Confirme Seu E-mail - Silva Shop',
            html: `
                <p>Olá ${name},</p>
                <p>Obrigado por se cadastrar na Silva Shop! Por favor, use o código abaixo para verificar seu e-mail e ativar sua conta:</p>
                <h3>Seu Código de Verificação: <strong>${verificationCode}</strong></h3>
                <p>Este código é válido por 1 hora.</p>
                <p>Se você não solicitou este cadastro, por favor, ignore este e-mail.</p>
                <p>Atenciosamente,<br>Equipe Silva Shop</p>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log('Email de verificação enviado para:', email);

        res.status(201).json({ message: 'Cadastro realizado com sucesso! Um código de verificação foi enviado para o seu e-mail.' });

    } catch (error) {
        console.error('Erro no cadastro:', error);
        res.status(500).json({ message: 'Erro no servidor durante o cadastro.' });
    }
});

// ROTA PARA CONFIRMAR O CÓDIGO DE VERIFICAÇÃO
app.post('/api/confirm-code', async (req, res) => {
    const { email, code } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'Usuário não encontrado.' });
        }

        if (user.isVerified) {
            return res.status(400).json({ message: 'Sua conta já está verificada.' });
        }

        // Verifica se o código expirou
        if (user.codeExpires && user.codeExpires < new Date()) {
            // Opcional: Remover o código expirado para que o usuário precise solicitar um novo
            user.verificationCode = undefined;
            user.codeExpires = undefined;
            await user.save();
            return res.status(400).json({ message: 'O código de verificação expirou. Por favor, solicite um novo.' });
        }

        // Verifica se o código é válido
        if (user.verificationCode !== code) {
            return res.status(400).json({ message: 'Código de verificação inválido.' });
        }

        // Marca a conta como verificada e remove o código
        user.isVerified = true;
        user.verificationCode = undefined;
        user.codeExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Conta verificada com sucesso! Você já pode fazer login.' });

    } catch (error) {
        console.error('Erro ao confirmar código:', error);
        res.status(500).json({ message: 'Erro no servidor ao confirmar código.' });
    }
});

// ROTA PARA REENVIAR O CÓDIGO DE VERIFICAÇÃO
app.post('/api/resend-code', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        if (user.isVerified) {
            return res.status(400).json({ message: 'Sua conta já está verificada. Não é necessário reenviar código.' });
        }

        const newCode = generateVerificationCode();
        user.verificationCode = newCode;
        user.codeExpires = new Date(Date.now() + 3600000); // Novo código expira em 1 hora
        await user.save();

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Reenvio de Código de Verificação - Silva Shop',
            html: `
                <p>Olá ${user.name || ''},</p>
                <p>Você solicitou um novo código de verificação. Por favor, use o código abaixo para ativar sua conta:</p>
                <h3>Seu Novo Código de Verificação: <strong>${newCode}</strong></h3>
                <p>Este código é válido por 1 hora.</p>
                <p>Se você não solicitou este reenvio, por favor, ignore este e-mail.</p>
                <p>Atenciosamente,<br>Equipe Silva Shop</p>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log('Novo email de verificação reenviado para:', email);

        res.status(200).json({ message: 'Um novo código de verificação foi enviado para o seu e-mail.' });

    } catch (error) {
        console.error('Erro ao reenviar código:', error);
        res.status(500).json({ message: 'Erro no servidor ao reenviar código.' });
    }
});


// ROTA DE LOGIN
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Credenciais inválidas.' });
        }

        // Verifica se a conta está verificada
        if (!user.isVerified) {
            return res.status(403).json({ message: 'Sua conta não foi verificada. Por favor, verifique seu e-mail para ativar a conta.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Credenciais inválidas.' });
        }

        // GERAÇÃO DO TOKEN JWT - USANDO process.env.JWT_SECRET
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: 'Login bem-sucedido!', token, userName: user.name });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ message: 'Erro no servidor durante o login.' });
    }
});


// Rota de exemplo protegida (requer token JWT)
app.get('/api/protected', (req, res) => {
    const token = req.headers.authorization && req.headers.authorization.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Acesso negado. Token não fornecido.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ message: `Bem-vindo, usuário ${decoded.userId}! Você acessou uma rota protegida.` });
    } catch (error) {
        console.error('Erro ao verificar token:', error);
        res.status(403).json({ message: 'Token inválido ou expirado.' });
    }
});


// Iniciar o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});