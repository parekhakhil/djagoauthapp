from django.shortcuts import render,redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import  User
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm

from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import  force_bytes,force_text,DjangoUnicodeDecodeError
from .utils import generate_token
from django.core.mail import EmailMessage
from django.contrib.auth.tokens import  PasswordResetTokenGenerator
from django.conf import settings
from django.contrib.auth import authenticate,login,logout
import threading

# Create your views here.

class EmailThread(threading.Thread):

    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()


class RegistrationView(View):
    def get(self, request):
        return render(request, 'auth/register.html')

    def post(self, request):
        context = {

            'data': request.POST,
            'has_error': False
        }

        email = request.POST.get('email')
        username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if len(password) < 6:
            messages.add_message(request, messages.ERROR,
                                 'passwords should be atleast 6 characters long')
            context['has_error'] = True
        if password != password2:
            messages.add_message(request, messages.ERROR,
                                 'passwords dont match')
            context['has_error'] = True

        if not validate_email(email):
            messages.add_message(request, messages.ERROR,
                                 'Please provide a valid email')
            context['has_error'] = True

        try:
            if User.objects.get(email=email):
                messages.add_message(request, messages.ERROR, 'Email is taken')
                context['has_error'] = True

        except Exception as identifier:
            pass

        try:
            if User.objects.get(username=username):
                messages.add_message(
                    request, messages.ERROR, 'Username is taken')
                context['has_error'] = True

        except Exception as identifier:
            pass

        if context['has_error']:
            return render(request, 'auth/register.html', context, status=400)

        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name = first_name
        user.last_name = last_name
        user.is_active = False
        user.save()
        
        current_site = get_current_site(request)
        email_subject = 'Activate account'
        message = render_to_string('auth/activate.html',{
            'user': user,
            'domain':current_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })

        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email],
            
        )
        #activation_email.send()
        EmailThread(email_message).start()
        messages.add_message(request, messages.SUCCESS,
                             'account created succesfully')

        return redirect('authapp:login')

        
class LoginView(View):
    def get(self,request):
        return render(request,'auth/login.html')

    def post(self,request):
        context = {
            'data' : request.POST,
            'has_error' : False
        }
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == '':
            messages.add_message(request,messages.ERROR,'Username or Email required')
            context['has_error'] = True
        
        if password == '':
            messages.add_message(request,messages.ERROR,'Password required')
            context['has_error'] = True
        
        user = authenticate(request,username=username,password=password)

        if not user and not context['has_error']:
            messages.add_message(request,messages.ERROR,'Invalid login credentials.')
            context['has_error'] = True

        if context['has_error']:
            return render(request,'auth/login.html',status=401,context=context)
        login(request,user)
        return redirect('authapp:home')

    
    

class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as identifier:
            user = None

        if user is not None and generate_token.check_token(user,token):
            user.is_active =True
            user.save()
            #messages.add_message(request,messages.success,'Account activated successfully!!!')
            messages.add_message(request, messages.SUCCESS,
                                 'account activated successfully')
            return redirect('authapp:login')
        return render(request,'auth/activation_failed.html',status=401)


class HomeView(View):
    def get(self, request):
        return render(request, 'home.html')


class LogoutView(View):
    def post(self, request):
        logout(request)
        messages.add_message(request, messages.SUCCESS, 'Logout successfully')
        return redirect('authapp:login')

    
class RequestResetEmailView(View):
    def get(self, request):
        return render(request,'auth/request-reset-email.html')
    
    def post(self, request):
        email = request.POST.get('email')

        if not validate_email(email):
            messages.error(request,"please enter valid email")
            return render(request,"auth/request-reset-email.html")

        user = User.objects.filter(email=email)

        if user.exists():
            current_site = get_current_site(request)
            email_subject = 'Reset password'
            message = render_to_string('auth/reset-password-email.html',{
                'domain':current_site.domain,
                'uid':urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0])
            })

            email_message = EmailMessage(
                email_subject,
                message,
                settings.EMAIL_HOST_USER,
                [email],
                
            )
            EmailThread(reset_email).start()

        messages.success(request,"We have sent you an email with reset link")
        return render(request,"auth/request-reset-email.html")


class ResetPasswordView(View):
    def get(self,request,uidb64,token):
        context = {
            
            'uidb64' : uidb64,
            'token': token
        }
        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))

            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.info(
                    request, 'Password reset link, is invalid, please request a new one')
                return render(request, 'auth/request-reset-email.html')

        except DjangoUnicodeDecodeError as identifier:
            messages.success(
                request, 'Invalid link')
            return render(request, 'auth/request-reset-email.html')
        return render(request,"auth/reset-password.html",context)

    def post(self,request,uidb64,token):
        context = {
            
            'uidb64' : uidb64,
            'token': token,
            'has_error': False,
        }

        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        if len(password) < 6:
            messages.add_message(request, messages.ERROR,
                                 'passwords should be atleast 6 characters long')
            context['has_error'] = True
        if password != password2:
            messages.add_message(request, messages.ERROR,
                                 'passwords dont match')
            context['has_error'] = True

        if context['has_error'] == True:

            return render(request,"auth/reset-password.html",context)
        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request,"Password reset successfully!!")
            return redirect('authapp:login')
        except DjangoUnicodeDecodeError as identifier:
             messages.error("Something went wrong")
             return render(request,"auth/reset-password.html",context)

 #       user_id = force_text(urlsafe_base64_decode(uidb64))

        return render(request,"auth/reset-password.html",context)

'''
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return redirect('authapp:change_password')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'authapp/change_password.html', {
        'form': form
    })
'''