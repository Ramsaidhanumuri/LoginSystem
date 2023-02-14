from turtle import title
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from LoginProject import settings
from django.core.mail import send_mail, EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token
from django.contrib.auth.decorators import login_required

# Create your views here.
def index(request):
    title = 'Django Project'
    return render(request, 'index.html', {'title':title})

def signup(request):
    title = 'SignUp'
    if request.method == 'POST':
        username = request.POST['Username']
        first_name = request.POST['fname']
        last_name = request.POST['lname']
        email = request.POST['Email']
        pass1 = request.POST['Password']
        pass2 = request.POST['CPassword']

        if User.objects.filter(username=username):
            messages.error(request, 'Username Already Exists!')
            return redirect('signup')
        elif User.objects.filter(email=email):
            messages.error(request, 'Email already Exists!')
            return redirect('signup')
        
        if len(username)<8:
            messages.error(request, 'Username must be 8 characters')
            return redirect('signup')
        
        if pass1 != pass2:
            messages.error(request, 'Password doesnot match with Confirm Password')
            return redirect('signup')

        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = first_name
        myuser.last_name = last_name
        myuser.is_active = False

        myuser.save()

        messages.success(request, 'Your account has been successfully created!. We have sent a confirmation mail, Please activate your account.')

        #Welcome Email
        subject = 'Welcome to Django Project - Django Login'
        message = 'Hello '+myuser.first_name +' '+ myuser.last_name + '!\n\n' + 'Welcome to Django Projects!! \n\nThank you for creating your account. \nConfirmation email have be sent to your email.\nPlease confirm your email address in order to activate your account. \n\nThanking You \nThe Django Project Team'
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        #Email Confirmation
        curren_site = get_current_site(request)
        email_subject = 'Confirm your email @ Django Project - Login!'
        message2 = render_to_string('email_confirmation.html', {
            'name' :myuser.first_name,
            'domain': curren_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token':generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email]
        )

        email.fail_silently = True
        email.send()

        return redirect('signin')

    return render(request, 'signup.html', {'title':title})

def signin(request):
    title = 'Sign In'
    if request.method == 'POST':
        username = request.POST['Username']
        pass1 = request.POST['Password']

        if not User.objects.filter(username=username):
            messages.error(request, 'Invalid Username')
            return redirect('signin')
        # elif not User.objects.filter(password=pass1):
        #     messages.error(request, 'Invalid Password')
        #     return redirect('signin')

        user = authenticate(username=username, password=pass1)

        if user is not None:
            login(request, user)
            fname = user.first_name
            messages.success(request, 'Succefully logged In!')
            return render(request, 'home.html', {'fname': fname})
        
        else:
            messages.error(request, 'Invalid Credentials!')
            return redirect('signin')

    return render(request, 'signin.html', {'title':title})

@login_required(login_url='signin')
def home(request):
    title = 'Home'
    return render(request, 'home.html', {'title':title})

@login_required(login_url='signin')
def signout(request):
    logout(request)
    title = 'SignOut'
    messages.success(request, 'Logout Successfully')
    return render(request, 'signout.html', {'title':title})

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None
    
    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        title = 'User Activation'
        myuser.save()
        login(request, myuser)
        fname = myuser.first_name
        messages.success(request, 'Your Email Was Verified Successfully!!!')
        return render(request, 'email_confirm_page.html', {'fname': fname, 'title':title})
    else:
        return render(request, 'activation_fail.html')

def email_confirm(request):
    title = 'User Activation'
    return render(request, 'email_confirm_page.html', {'title':title})

def reset(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None
    
    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        fname = myuser.first_name
        return render(request, 'update_password.html', {'uid':uid, 'fname':fname})
    else:
        return render(request, 'activation_fail.html')
    
def reset_pass(request):
    title = 'Forgot Password'
    if request.method=='POST':
        email = request.POST['Email']

        if not User.objects.filter(email=email):
            messages.error(request, 'Email Not Registered')
            return redirect('reset_password')
        else:
            #Reset Mail
            myuser = User.objects.get(email=email)

            curren_site = get_current_site(request)
            email_subject = 'Password Reset @ Django Project'
            message2 = render_to_string('email_password_reset.html', {
                'name' :myuser.first_name,
                'domain': curren_site.domain,
                'uid':urlsafe_base64_encode(force_bytes(myuser.pk)),
                'token':generate_token.make_token(myuser)
            })
            email = EmailMessage(
                email_subject,
                message2,
                settings.EMAIL_HOST_USER,
                [myuser.email]
            )

            email.fail_silently = True
            email.send()
            
            messages.success(request, 'Reset Password link was successfully sent to your registered email')

            return redirect('reset_password')

    return render(request, 'reset_password.html', {'title':title})

def update_password(request):
    title = 'Update Password'
    if request.method=='POST':
        uid = request.POST['uid']
        npass = request.POST['Npass']
        cpass = request.POST['Cpass']

        myuser = User.objects.get(pk=uid)

        if npass != cpass:
            messages.error(request, 'New Password and Confirm Password not matched')
            return render(request, 'update_password.html', {'uid':uid, 'fname':myuser.first_name})
        
        elif npass == cpass:
            myuser.set_password(npass)
            myuser.save()
            return render(request, 'update_password.html', {'uid':uid, 'fname':myuser.first_name})

    return render(request, 'update_password.html', {'title':title})