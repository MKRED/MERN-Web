import React, { useContext, useEffect, useState } from 'react'
import { AuthContext } from '../context/AuthContext'
import { useHttp } from '../hooks/http.hook'
import { useMessage } from '../hooks/message.hook'


export const AuthPage = () => {
    const auth = useContext(AuthContext)

    const message = useMessage()

    const {loading, request, error, clearError} = useHttp()

    const [form, setForm] = useState({
        login: '', password: ''
    })

    useEffect( () => {
        message(error)
        clearError()
    }, [error, message, clearError])

    useEffect( () => {
        window.M.updateTextFields()
    }, [])

    const changeHandler = event => {
        setForm({ ...form, [event.target.name]: event.target.value })
    }

    const registerHandler = async () => {
        try {
            const data = await request('/api/auth/register', 'POST', {...form})
            message("Пользователь создан")
            //message(data.message) // why not work??
        } catch (e) {

        }
    }

    const loginHandler = async () => {
        try {
            const data = await request('/api/auth/login', 'POST', {...form})
            auth.login(data.token, data.userId)
            message("Успешный вход")
            //message(data.message) // why not work??
        } catch (e) {

        }
    }

    return (
        <div className="row">
            <div className="col s6 offset-s3">
                <h1>Сократи Cсылку!</h1>
                <div className="card blue darken-1">
                    <div className="card-content white-text">
                        <span className="card-title">Авторизация</span>
                        <div>
                            
                        <div className="input-field">
                            <input 
                            placeholder="Введите логин" 
                            id="first_name" 
                            type="text" 
                            name="login"
                            className="yellow-input"
                            value={form.login}
                            onChange={changeHandler}
                            />
                        <label htmlFor="first_name">Логин</label>
                        </div>

                        <div className="input-field">
                            <input 
                            placeholder="Введите пароль" 
                            id="password" 
                            type="password" 
                            name="password"
                            className="yellow-input"
                            value={form.password}
                            onChange={changeHandler}
                            />
                        <label htmlFor="password">Пароль</label>
                        </div>

                        </div>
                    </div>
                    <div className="card-action">
                        <button 
                            className="btn yellow darken-4" 
                            style={{marginRight: 10}}
                            onClick={loginHandler}
                            disabled={loading}
                            >
                            Войти
                            </button>
                        <button 
                            className="btn grey lighten-1 black-text"
                            onClick={registerHandler}
                            disabled={loading}
                            >
                            Регистрация
                            </button>
                    </div>
                </div>
            </div>
        </div>
    )
}