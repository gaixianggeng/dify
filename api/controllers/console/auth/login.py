# -*- coding:utf-8 -*-
import flask
import flask_login
from flask import request, current_app
from flask_restful import Resource, reqparse

import services
from controllers.console import api
from controllers.console.error import AccountNotLinkTenantError
from controllers.console.setup import setup_required
from libs.helper import email
from libs.password import valid_password
from services.account_service import AccountService, TenantService
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.utils import make_msgid
import time 




class LoginApi(Resource):
    """Resource for user login."""

    @setup_required
    def post(self):
        """Authenticate user and login."""
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=email, required=True, location='json')
        parser.add_argument('password', type=valid_password, required=True, location='json')
        parser.add_argument('remember_me', type=bool, required=False, default=False, location='json')
        args = parser.parse_args()

        # todo: Verify the recaptcha

        try:
            # account = AccountService.authenticate(args['email'], args['password'])
            account = AccountService.authenticate_verify_code(args['email'],args['password'])
        except services.errors.account.AccountLoginError:
            return {'code': 'unauthorized', 'message': 'Invalid email or password'}, 401

        try:
            TenantService.switch_tenant(account)
        except Exception:
            raise AccountNotLinkTenantError("Account not link tenant")

        flask_login.login_user(account, remember=args['remember_me'])
        AccountService.update_last_login(account, request)

        # todo: return the user info

        return {'result': 'success'}


class LogoutApi(Resource):

    @setup_required
    def get(self):
        flask.session.pop('workspace_id', None)
        flask_login.logout_user()
        return {'result': 'success'}

class VerifyCodeApi(Resource):

    @setup_required
    def post(self):
        """Authenticate user and login."""
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=email, required=True, location='json')
        args = parser.parse_args()

        # todo: Verify the recaptcha
        try:
            account = AccountService.judge_account_exist(args['email'])
        except services.errors.account.AccountLoginError:
            return {'code': 'unauthorized', 'message': 'Invalid email'}, 401

        try:
            TenantService.switch_tenant(account)
        except Exception:
            raise AccountNotLinkTenantError("Account not link tenant")

        code = AccountService.generate_verfiy_code()   
        sendMail(args['email'], code=code)        
        """ save code to redis """
        AccountService.save_code(args['email'], code)
        # todo: return the user info

        return {'result': 'success'}


def sendMail(to, code):
    send = "support@code89757.com"
    sendMailPassword = "nKg5uebnrgURPVe3"
     # read html file
    with open('./assets/verify.html', 'r') as f:
        content = f.read()

    # replace code in the content
    body = content.replace('{code}', code, 1)

    # create MIMEText object
    msg = MIMEText(body, 'html', 'utf-8')

    # specify headers
    msg['From'] = Header(f"AI.89757 <{send}>")
    msg['To'] = Header(to, 'utf-8')
    msg['Subject'] = Header('AI.89757 登录验证码', 'utf-8')
    msg['Content-Type'] = 'text/html; charset=UTF-8'
    msg['Message-ID'] = make_msgid(domain='localhost')

    # send mail
    try:
        server = smtplib.SMTP_SSL("hwsmtp.exmail.qq.com", 465)
        server.login(send, sendMailPassword)
        server.sendmail(send, [to], msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Error occurred: {e}")



class ResetPasswordApi(Resource):
    @setup_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=email, required=True, location='json')
        args = parser.parse_args()

        # import mailchimp_transactional as MailchimpTransactional
        # from mailchimp_transactional.api_client import ApiClientError

        account = {'email': args['email']}
        # account = AccountService.get_by_email(args['email'])
        # if account is None:
        #     raise ValueError('Email not found')
        # new_password = AccountService.generate_password()
        # AccountService.update_password(account, new_password)

        # todo: Send email
        MAILCHIMP_API_KEY = current_app.config['MAILCHIMP_TRANSACTIONAL_API_KEY']
        # mailchimp = MailchimpTransactional(MAILCHIMP_API_KEY)

        message = {
            'from_email': 'noreply@example.com',
            'to': [{'email': account.email}],
            'subject': 'Reset your Dify password',
            'html': """
                <p>Dear User,</p>
                <p>The Dify team has generated a new password for you, details as follows:</p> 
                <p><strong>{new_password}</strong></p>
                <p>Please change your password to log in as soon as possible.</p>
                <p>Regards,</p>
                <p>The Dify Team</p> 
            """
        }

        # response = mailchimp.messages.send({
        #     'message': message,
        #     # required for transactional email
        #     ' settings': {
        #         'sandbox_mode': current_app.config['MAILCHIMP_SANDBOX_MODE'],
        #     },
        # })

        # Check if MSG was sent
        # if response.status_code != 200:
        #     # handle error
        #     pass

        return {'result': 'success'}


api.add_resource(LoginApi, '/login')
api.add_resource(LogoutApi, '/logout')
api.add_resource(VerifyCodeApi, '/send_verify_code')
