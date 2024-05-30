<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        require_once str_replace("".DIRECTORY_SEPARATOR."Providers","".DIRECTORY_SEPARATOR."Http".DIRECTORY_SEPARATOR."functions.php",__DIR__);
    }
}
