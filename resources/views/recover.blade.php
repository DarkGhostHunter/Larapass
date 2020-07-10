@extends('larapass::layout')

@section('title', trans('larapass::recovery.title'))

@section('body')
    <form id="form">
        <input type="hidden" name="email" value="{{ $email }}">
        <input type="hidden" name="token" value="{{ $token }}">
        <h2 class="card-title h5 text-center">{{ trans('larapass::recovery.title') }}</h2>
        <hr>
        <p>{{ trans('larapass::recovery.instructions') }}</p>
        @if ($errors->any())
            <div class="alert alert-danger small">
                <ul>
                    @foreach ($errors->all() as $error)
                        <li>{{ $error }}</li>
                    @endforeach
                </ul>
            </div>
        @endif
        <div class="form-group text-center">
            <div class="custom-control custom-checkbox">
                <input type="checkbox" class="custom-control-input" id="unique">
                <label class="custom-control-label" for="unique">{{ trans('larapass::recovery.unique') }}</label>
            </div>
        </div>
        <div class="text-center">
            <button type="submit" class="btn btn-primary btn-lg">
                {{ trans('larapass::recovery.button.register') }}
            </button>
        </div>
    </form>
@endsection

@push('scripts')
    <script src="{{ asset('vendor/larapass/js/larapass.js') }}"></script>
    <script>
        const larapass = new Larapass({
            register: '/webauthn/recover/register',
            registerOptions: '/webauthn/recover/options'
        })

        document.getElementById('form').addEventListener('submit', function (event) {
            event.preventDefault()

            let entries = Object.fromEntries(new FormData(this).entries())

            larapass.register(entries, {
                token: entries.token,
                email: entries.email,
                'WebAuthn-Unique': entries.unique ? true : false,
            })
                .then(response => window.location.replace(response.redirectTo))
                .catch(response => {
                    alert('{{ trans('larapass::recovery.failed') }}')
                    console.error('Recovery failed', response)
                })
        })
    </script>
@endpush