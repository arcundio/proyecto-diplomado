import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Login.css';

function Login() {
    const navigate = useNavigate();
    const [email, setEmail] = useState('');
    const [passwrd, setPasswrd] = useState('');

    const handleRegisterClick = () => {
        navigate('/register');
    };

    const handleGoogleLogin = () => {
        window.location.href = 'https://backend:8505/auth/google';
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        try {
            const response = await fetch('https://backend:8505/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, passwrd }),
            });

            if (response.ok) {
                const { token, userID } = await response.json(); // Asegúrate de que el backend:8505 devuelva userID
                localStorage.setItem('jwt', token);
                localStorage.setItem('userID', userID); // Guardar el userID
                navigate('/data');
            } else {
                const errorText = await response.text();
                alert(`Error: ${errorText}`);
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Ocurrió un error');
        }
    };

    return (
        <div className="container">
            <div className="login-container">
                <div className="form-container">
                    <h2>Login</h2>
                    <form onSubmit={handleSubmit}>
                        <label htmlFor="email">Correo electrónico:</label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                        <label htmlFor="passwrd">Contraseña:</label>
                        <input
                            type="password"
                            id="passwrd"
                            name="passwrd"
                            value={passwrd}
                            onChange={(e) => setPasswrd(e.target.value)}
                            required
                        />
                        <button className="button-85" role="button" type="submit">
                            <span className="text">Login</span>
                        </button>
                    </form>
                    <p className="register-link" onClick={handleRegisterClick}>
                        No tengo cuenta
                    </p>
                    <button onClick={handleGoogleLogin} className="button-google">
                        Iniciar sesión con Google
                    </button>
                </div>
            </div>
        </div>

    );
}

export default Login;
