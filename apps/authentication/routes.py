# -*- encoding: utf-8 -*-

import json
from datetime import datetime
import os, re

# Importações do Flask e extensões relacionadas
from flask_restx import Resource, Api
import flask
from flask import render_template, redirect, request, url_for, send_file
from flask_login import (
    current_user,
    login_user,
    logout_user
)
from flask_dance.contrib.github import github

# Importações dos modelos, formulários e utilitários de autenticação
from apps import db, login_manager
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm
from apps.authentication.models import Users
from apps.authentication.util import verify_pass, generate_token

# Rota padrão redireciona para a página de login
@blueprint.route('/')
def route_default():
    return redirect(url_for('authentication_blueprint.login'))



# Rota para login de usuários
@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)

    if flask.request.method == 'POST':
        # Ler os dados do formulário
        username = request.form['username']
        password = request.form['password']
        #retorna 'Login: ' + username + ' / ' + password

        # Localizar o usuário
        user = Users.query.filter_by(username=username).first()

        # Verificar a senha
        if user and verify_pass(password, user.password):
            login_user(user)
            return redirect(url_for('authentication_blueprint.route_default'))

        # Caso usuário ou senha estejam incorretos
        return render_template('accounts/login.html',
                               msg='Usuário ou senha errados',
                               form=login_form)

    # Redirecionar usuário logado para a página inicial
    if current_user.is_authenticated:
        return redirect(url_for('home_blueprint.index'))
    else:
        return render_template('accounts/login.html',
                               form=login_form) 

# Rota para registro de novos usuários
@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username = request.form['username']
        email = request.form['email']

        # Verificar se o nome de usuário já está em uso
        user = Users.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Usuário já registrado',
                                   success=False,
                                   form=create_account_form)

        # Verificar se o e-mail já está em uso
        user = Users.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='E-mail já registrado',
                                   success=False,
                                   form=create_account_form)

        # Senão podemos criar o usuário
        user = Users(**request.form)
        db.session.add(user)
        db.session.commit()

        # Redirecionar para a página de registro com mensagem de sucesso
        logout_user()

        return render_template('accounts/register.html',
                               msg='Usuário criado com sucesso.',
                               success=True,
                               form=create_account_form)
    # Renderizar formulário de registro
    else:
        return render_template('accounts/register.html', form=create_account_form)

# Endpoint para autenticação via JWT (JSON Web Tokens)
@blueprint.route('/login/jwt/', methods=['POST'])
class JWTLogin(Resource):
    def post(self):
        try:
            data = request.form

            if not data:
                data = request.json

            if not data:
                return {
                           'message': 'Nome de usuário ou senha está faltando',
                           "data": None,
                           'success': False
                       }, 400
            # Validar entrada
            user = Users.query.filter_by(username=data.get('username')).first()
            if user and verify_pass(data.get('password'), user.password):
                try:

                    # Gerar token se não existir ou estiver vazio
                    if not user.api_token or user.api_token == '':
                        user.api_token = generate_token(user.id)
                        user.api_token_ts = int(datetime.utcnow().timestamp())
                        db.session.commit()

                    # Token deve expirar após 24 horas
                    return {
                        "message": "Token de autenticação obtido com sucesso",
                        "success": True,
                        "data": user.api_token
                    }
                except Exception as e:
                    return {
                               "error": "Algo deu errado",
                               "success": False,
                               "message": str(e)
                           }, 500
            return {
                       'message': 'Nome de usuário ou senha está errado',
                       'success': False
                   }, 403
        except Exception as e:
            return {
                       "error": "Algo deu errado",
                       "success": False,
                       "message": str(e)
                   }, 500

# Rota para logout de usuários
@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login')) 

# Manipulador de erro para acesso não autorizado
@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('home/page-403.html'), 403

# Manipulador de erro para acesso proibido (403)
@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('home/page-403.html'), 403

# Manipulador de erro para página não encontrada (404)
@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('home/page-404.html'), 404

# Manipulador de erro interno do servidor (500)
@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500




