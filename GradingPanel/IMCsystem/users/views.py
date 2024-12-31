from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from datetime import timedelta
from django.utils import timezone
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile
import secrets
import pyotp
import base64
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
import binascii

User = get_user_model()

def base32_to_hex(base32_secret):
    # Convert Base32 to bytes
    base32_bytes = base64.b32decode(base32_secret.upper() + '=' * ((8 - len(base32_secret)) % 8))
    # Convert bytes to hex
    return binascii.hexlify(base32_bytes).decode()



# Create your views here.
def home(request):
    return render(request, "home.html")


# def register2(request):
#     if request.method == "POST":
#         username = request.POST["username"]
#         uid = request.POST["uid"]
#         email = request.POST["email"]
#         password = request.POST["password"]
#         password2 = request.POST["password2"]

#         if password == password2:
#             if User.objects.filter(email=email).exists():  # Check if email is already registered
#                 messages.info(request, "Email Already Used")
#                 return redirect('register')
#             elif User.objects.filter(username=username).exists():
#                 messages.info(request, "Username Already Used")
#                 return redirect("register")
#             elif User.objects.filter(uid=uid).exists():
#                 messages.info(request, "UID Already Used")
#                 return redirect("register")
#             else:
#                 # Create a new student with custom fields
#                 student = User.objects.create_user(
#                     username=username, 
#                     email=email, 
#                     password=password,
#                     uid=uid
#                 )
#                 student.save()
                
#                 # Optional: If you want to set some initial values for other fields
#                 # student.passed_SDCA = False  # or whatever the default should be
#                 # student.save()

#                 return redirect("login")
#         else:
#             messages.info(request, "Passwords don't match")
#             return redirect("register")
#     else:
#         return render(request, "register.html")
    
def login2(request):
    if request.method == "POST":
        uid = request.POST["uid"]
        password = request.POST["password"]

        user = auth.authenticate(request, uid=uid, password=password)

        if user is not None:
            auth.login(request, user)
            return redirect("dashboard", uid=uid)  # Redirect to dynamic URL
        else:
            messages.info(request, "Credentials Invalid")
            return redirect("login")
        
    else:
        return render(request, "login.html")
    
def login(request):
    if request.method == "POST":
        uid = request.POST.get("uid")
        password = request.POST.get("password")
        totp = request.POST.get("totp")

        # Authenticate user with UID and password
        user = authenticate(request, uid=uid, password=password)

        if user is not None:
            # Check if user has a TOTP device configured
            if user.totp_device and user.totp_device.confirmed:
                # Verify TOTP
                totp_device = user.totp_device
                if totp_device.verify_token(totp):
                    auth_login(request, user)
                    return redirect("dashboard", uid=uid)
                else:
                    messages.error(request, "Invalid TOTP code. Please try again.")
            else:
                # If no TOTP device or not confirmed, you might want to handle this case
                # Here we assume all users must have TOTP for login
                messages.error(request, "TOTP is not configured or confirmed for this account.")
        else:
            messages.error(request, "Invalid UID or password.")

        # If we reach here, authentication failed or TOTP was incorrect
        return redirect("login")
    else:
        return render(request, "login.html")


@login_required(login_url='login')  # Redirect to 'login' if not authenticated
def dashboard(request, uid):
    # Check if the uid in URL matches the authenticated user's uid
    user = get_object_or_404(User, uid=uid)
    
    if request.user != user:
        # If the UID doesn't match the logged-in user, redirect to login or wherever
        return redirect('login')
    
    context = {
        'uid': uid
    }
    
    return render(request, 'dashboard.html', context)






def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        uid = request.POST["uid"]
        email = request.POST["email"]
        password = request.POST["password"]
        password2 = request.POST["password2"]

        if password == password2:
            if User.objects.filter(email=email).exists():
                messages.info(request, "Email Already Used")
                return redirect('register')
            elif User.objects.filter(username=username).exists():
                messages.info(request, "Username Already Used")
                return redirect("register")
            elif User.objects.filter(uid=uid).exists():
                messages.info(request, "UID Already Used")
                return redirect("register")
            else:
                # Create user
                user = User.objects.create_user(username=username, email=email, password=password, uid=uid)
                
                # Generate TOTP secret for new user
                secret = secrets.token_urlsafe(32)
                secret_bytes = base64.urlsafe_b64decode(secret.encode('utf-8') + b'=' * (4 - len(secret) % 4))
                secret_base32 = base64.b32encode(secret_bytes).decode('utf-8').rstrip('=')
                hex_secret = base32_to_hex(secret_base32)

                totp_device = TOTPDevice(
                    user=user,
                    name="Default TOTP Device",
                    confirmed=True,
                    key=hex_secret  # Ensure 'key' is correctly set to the base32 secret
                )
                totp_device.save()  # This should work now without confusion

                # Save TOTP device to user
                user.totp_device = totp_device
                user.save()

                # Use pyotp for provisioning URI
                totp = pyotp.TOTP(secret_base32)
                otpauth_url = totp.provisioning_uri(name=user.email, issuer_name='IMC')

                # Generate QR code
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(otpauth_url)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")

                buffer = BytesIO()
                img.save(buffer, format="PNG")
                qr_code_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
                
                # Store secret and qr_code in session for verification
                request.session['otp_secret'] = secret_base32
                request.session['qr_code'] = qr_code_base64

                return redirect('verify_totp')  # Redirect to OTP verification step

        else:
            messages.info(request, "Passwords don't match")
            return redirect("register")
    else:
        return render(request, "register.html")

@login_required
def verify_totp(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')
        user = request.user
        secret = request.session.get('otp_secret')
        
        if secret:
            # Create a TOTP object with the secret from the session
            totp = pyotp.TOTP(secret)
            
            if totp.verify(otp):
                # If OTP is correct, confirm the TOTP device
                totp_device = user.totp_device
                
                if not totp_device:  # Check if the device exists
                    # If no device exists, create one now
                    totp_device = TOTPDevice(
                        user=user,
                        name="Default TOTP Device",
                        confirmed=True,  # Now confirmed since we verified the OTP
                        key=secret
                    )
                    totp_device.save()
                    user.totp_device = totp_device
                    user.save()
                else:
                    totp_device.confirmed = True
                    totp_device.save()
                
                # Clean up session
                request.session.pop('otp_secret', None)
                request.session.pop('qr_code', None)
                
                return redirect("login")  # Redirect only if verification is successful
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
                # If verification fails, render the same page with the error message
                qr_code = request.session.get('qr_code')
                return render(request, 'verify_totp.html', {'qr_code': qr_code, 'error': 'Invalid OTP. Please try again.'})
        else:
            messages.error(request, 'OTP secret not found in session. Please register again.')
            return render(request, 'verify_totp.html', {'error': 'OTP secret not found in session. Please register again.'})
    
    # For GET requests
    qr_code = request.session.get('qr_code')
    return render(request, 'verify_totp.html', {'qr_code': qr_code})