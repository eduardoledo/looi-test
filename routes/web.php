<?php

use App\Http\Controllers\TodoAppiController;
use App\Models\Todo;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Route::get('/api', [TodoAppiController::class, 'index'])->middleware('auth:sanctum');
Route::post('/api/new', [TodoAppiController::class, 'store']);
Route::put('/api/update/{id}', [TodoAppiController::class, 'update']);
Route::delete('/api/delete/{id}', [TodoAppiController::class, 'destroy']);

Route::post('/register', [TodoAppiController::class, 'register']);
Route::post('/login', [TodoAppiController::class, 'login']);

