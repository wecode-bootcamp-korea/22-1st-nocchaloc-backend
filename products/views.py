import json
from math import ceil

from django.views     import View
from django.db.models import Q, Count
from django.http      import JsonResponse

from products.models import Product, Category, Option, Review, Video
from utils import authorization

class ProductView(View):

    def get(self, request):
        sort_dic = {
            '1': '-is_new',
            '2': '-price',
            '3': 'price',
            'm': '-view_count'}
        MAIN_AMOUNT  = 10
        PAGE_SIZE    = 24
        product_type = request.GET.getlist('product_type', None)
        category     = request.GET.get('category', None)
        sort         = request.GET.get('sort', '1')
        page         = request.GET.get('page', None)
        limit        = int(request.GET.get('limit', PAGE_SIZE))
        offset       = int(request.GET.get('offset', 0))

        q = Q()
        if category:
            q &= Q(category_id = category)
        if product_type:
            q &= Q(product_type_id__in = product_type)

        total_products = Product.objects.filter(q).order_by(sort_dic[sort])
        total_page     = ceil(total_products.count()/PAGE_SIZE)
        products       = total_products[offset:limit]

        if page == 'm':
            products = Product.objects.filter(q).order_by(sort_dic[page])[0:MAIN_AMOUNT]

        products_info = [{
            "name"            : product.name,
            "price"           : product.price,
            "main_image_url"  : product.main_image_url,
            "hover_image_url" : product.hover_image_url,
            "pk"              : product.pk         if page != 'm' else None,
            "view_count"      : product.view_count if page != 'm' else None,
            "is_new"          : product.is_new     if page != 'm' else None
        } for product in products]

        data = [{
            "total_page"     : total_page,
            "total_products" : total_products.count()
        }]

        categories = Category.objects.all()
        category_info = [{"name" : category.name} for category in categories]

        videos = Video.objects.all()
        video_info = [{
            "name"        : video.name,
            "description" : video.description,
            "video_url"   : video.video_url
        } for video in videos]

        return JsonResponse({"products_info":products_info, "category_info":category_info, "data":data, "video":video_info}, status=200)

class ProductDetailView(View):
    def get(self, request, product_id):
        product = Product.objects.get(id=product_id)
        product_info = [{
            "name"           : product.name,
            "price"          : product.price,
            "main_image_url" : product.main_image_url,
            "description"    : product.description
        }]

        product.view_count += 1
        product.save()

        options = Option.objects.all()
        option_info = [{
            "option_name"  : option.name,
            "option_price" : option.price
        } for option in options]

        return JsonResponse({"product_info":product_info, "option_info":option_info}, status=200)

class ProductReviewView(View):
    @authorization
    def post(self, request):
        data = json.loads(request.body)
        try:
            if not Product.objects.filter(id=data['product_id']).exists():
                return JsonResponse({'MESSAGE':'INVALID_ERROR'},status=401)
            Review.objects.create(
                user       = request.user,
                product_id = data['product_id'],
                comment    = data['comment'],
                score      = data['score']
            )
            return JsonResponse({'MESSAGE':'SUCCESS'}, status=201)
        except KeyError:
            return JsonResponse({'MESSAGE':'KEY_ERROR'}, status=400)

    def get(self, request):
        try:
            product_id = request.GET['product_id']
            if Product.objects.filter(id=product_id).exists():
                reviews = Review.objects.filter(product=product_id)

                product_review=[{
                    "user"        : review.user.account,
                    "comment"     : review.comment,
                    "score"       : review.score,
                    "create_time" : review.create_time,
                    "update_time" : review.update_time} for review in reviews]

                return JsonResponse({'product':product_id,'result':product_review},status=200)
            return JsonResponse({'message':'VALUE_ERROR'},status=404)
        except KeyError:
            return JsonResponse({'message':'KEY_ERROR'}, status=400)
        except TypeError:
            return JsonResponse({'message':'TYPE_ERROR'}, status=400)
        except ValueError:
            return JsonResponse({'message':'UNAUTHORIZED'}, status=401)

    @authorization
    def delete(self, request, review_id):
        try:
            if Review.objects.filter(id=review_id).exists():
                Review.objects.get(id=review_id).delete()
                return JsonResponse({'message':'SUCCESS'},status=200)
            return JsonResponse({'message':'VALUE_ERROR'},status=404)

        except KeyError:
            return JsonResponse({'message':'KEY_ERROR'}, status=400)
        except TypeError:
            return JsonResponse({'message':'TYPE_ERROR'}, status=400)
        except ValueError:
            return JsonResponse({'message':'UNAUTHORIZED'}, status=401)

class SearchView(View):
    def post(self, request):
        try:
            page        = int(request.GET.get('page', 1))
            PAGE_SIZE   = 24
            limit       = int(PAGE_SIZE * page)
            offset      = int(limit - PAGE_SIZE)
            
            word        = request.GET.get('word', None)
            search_list = Product.objects.filter(Q(name__icontains=word) | Q(description__icontains=word)).annotate(review_count=Count('review')).order_by('-review_count')[offset:limit]
            context     = [{
                'name'           :search.name,
                'price'          :search.price,
                'main_image_url' :search.main_image_url,
                'hover_image_url':search.hover_image_url
            } for search in search_list]

            return JsonResponse({'search_list':context, 'search_word':word}, status = 200)
        except KeyError:
            return JsonResponse({'message':'KEY_ERROR'}, status=400)
        except TypeError:
            return JsonResponse({'message':'TYPE_ERROR'}, status=400)
        except ValueError:
            return JsonResponse({'message':'UNAUTHORIZED'}, status=401)