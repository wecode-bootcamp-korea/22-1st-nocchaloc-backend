import re,json,bcrypt,jwt

from django.views           import View
from django.http            import JsonResponse
from django.shortcuts       import render

from users.models           import User
from my_settings            import SECRET_KEY
from datetime               import datetime, timedelta
from utils                  import authorization
# Create your views here.

REGEX = {
    'account'  : '[a-zA-Z]\w{4,12}',
    'password' : '(?=.*[a-zA-Z])((?=.*\d)|(?=.*\W)).{8,16}'
}

class SignupView(View):
    def post(self, request):
        try:
            data     = json.loads(request.body)
            account  = data['account']
            password = data['password']

            if not re.match(REGEX['account'],account) or not re.match(REGEX['password'],password):
                return JsonResponse({'message':'INVALID_ERROR'},status=404)

            if User.objects.filter(account=data['account']).exists() or User.objects.filter(phone_number=data['phone_number']).exists():
                return JsonResponse({'message':'DUPLICATE'},status=409)

            encoded_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

            User.objects.create(
                phone_number = data['phone_number'],
                name         = data['name'],
                birthday     = data['birthday'],
                account      = data['account'],
                password     = encoded_password.decode('utf-8'),
                point        = 50000,
            )
            return JsonResponse({'message':'SUCCESS'},status=201)

        except KeyError:
            return JsonResponse({'message':'KEY_ERROR'},status=400)

class SigninView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            
            if not User.objects.filter(account=data['account']).exists():
                return JsonResponse({'message':'INVALID_USER'},status=409)

            account       = data['account']
            password      = data['password']
            user_id       = User.objects.get(account=account).id
            user_password = User.objects.get(account=account).password.encode('utf-8')

            if bcrypt.checkpw(data['password'].encode('utf-8'),user_password):
                encoded_jwt = jwt.encode({'user_id':user_id,'exp':datetime.utcnow()+timedelta(days=1)},SECRET_KEY,algorithm='HS256')
                return JsonResponse({'message':'SUCCESS','TOKEN':encoded_jwt},status=200)
            
            return JsonResponse({'message':'INVALID_USER'},status=401)

        except KeyError:
            return JsonResponse({'message':'KEY_ERROR'},status=400)

