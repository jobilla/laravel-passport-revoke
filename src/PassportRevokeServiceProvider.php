<?php

namespace Jobilla\PassportRevoke;

use Illuminate\Support\ServiceProvider;

class PassportRevokeServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->commands([RevokePassportTokens::class]);
    }
}
