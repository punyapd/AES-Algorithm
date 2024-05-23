from django.shortcuts import render
from django.http import JsonResponse
from .aes_utils import encrypt, decrypt, generate_key
import base64


def home(request):
    return render(request, "home.html")


def about(request):
    return render(request, "about.html")


def encrypt_decrypt(request):
    return render(request, "index.html")


def encrypt_view(request):
    if request.method == "POST":
        text = request.POST.get("text")
        key = base64.b64encode(
            generate_key()
        ).decode()  # Generate and encode key for user
        encrypted_text = encrypt(text, base64.b64decode(key))
        return JsonResponse({"encrypted_text": encrypted_text, "key": key})
    return JsonResponse({"error": "Invalid request"}, status=400)


def decrypt_view(request):
    if request.method == "POST":
        encrypted_text = request.POST.get("encrypted_text")
        key = request.POST.get("key")
        try:
            decrypted_text = decrypt(encrypted_text, base64.b64decode(key))
            return JsonResponse({"decrypted_text": decrypted_text})
        except Exception as e:
            return JsonResponse(
                {"error": "Decryption failed", "details": str(e)}, status=400
            )
    return JsonResponse({"error": "Invalid request"}, status=400)
