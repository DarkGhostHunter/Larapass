<!doctype html>
<html lang="{{ config('app.locale') }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css" integrity="sha384-B0vP5xmATw1+K9KRQjQERJvTumQW0nPEzvF6L/Z6nronJ3oUOFUFpCjEUQouq2+l" crossorigin="anonymous">
    <title>@yield('title')</title>
    <style>
        #box-container {
            min-height: 100vh;
        }
        #box {
            margin-bottom: 6rem;
        }
        .cool-shadow {
            box-shadow: 0 2.8px 2.2px rgba(0, 0, 0, 0.1),
            0 6.7px 5.3px rgba(0, 0, 0, 0.072),
            0 12.5px 10px rgba(0, 0, 0, 0.06),
            0 22.3px 17.9px rgba(0, 0, 0, 0.05),
            0 41.8px 33.4px rgba(0, 0, 0, 0.04),
            0 100px 80px rgba(0, 0, 0, 0.028);
        }
    </style>
</head>
<body class="bg-light">
<div class="container">
    <div id="box-container" class="row justify-content-center align-items-center">
        <div id="form-container" class="col-lg-6 col-md-8 col-sm-10 col-12">
            <div id="box" class="card border-0 cool-shadow">
                <section class="card-body">
                    @yield('body')
                </section>
            </div>
        </div>
    </div>
</div>
@stack('scripts')
</body>
</html>
