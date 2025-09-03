from django.shortcuts import render

def show_main(request):
    context = {
        'npm' : '2406453461',
        'name': 'Gunata Prajna Putra Sakri',
        'class': 'PBP KKI'
    }

    return render(request, "main.html", context)