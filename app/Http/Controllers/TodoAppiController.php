<?php

namespace App\Http\Controllers;

use App\Models\Todo;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Sanctum\PersonalAccessToken;

class TodoAppiController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $todos = $this->getUser()->todos()->getResults();
        return response()->json($todos);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validator = Validator::make(
            $request->all(),
            [
                'data' => ['required', 'string', 'max:255'],
            ]
        );
        if ($validator->fails()) {
            return response()->json(["status" => "failed", "message" => "Please Input Valid Data", "errors" => $validator->errors()]);
        }
        $user = $this->getUser();
        $todo = new Todo(["data" => $request->data]);

        $user->todos()
            ->save($todo);

        if (!is_null($todo)) {
            return response()->json(["status" => 200, "success" => true, "message" => "Creation completed successfully", "data" => $todo]);
        } else {
            return response()->json(["status" => "failed", "success" => false, "message" => "Error creating todo"])->setStatusCode(500);
        }
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request)
    {
        $todos = $this->getUser()
            ->todos();
        $todo = $todos
            ->where('id', $request->id)
            ->get()
            ->first();

        if (!is_null($todo)) {
            $todo->data = $request->data;
            $todos->save($todo);

            return response()->json(["status" => 200, "success" => true, "message" => "Update completed successfully", "data" => $todo]);
        } else {
            return response()->json(["status" => "failed", "success" => false, "message" => "ToDo not found"])->setStatusCode(404);
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Request $request)
    {
        $todos = $this->getUser()
            ->todos();
        $todo = $todos
            ->where('id', $request->id)
            ->get()
            ->first();
        //
        if (!is_null($todo)) {
            $todos->delete($todo);
            return response()->json(["status" => 200, "success" => true, "message" => "ToDo successfully deleted"]);
        } else {
            return response()->json(["status" => "failed", "success" => false, "message" => "ToDo not found"])->setStatusCode(404);
        }

        // return response()->json($todo);
    }

    public function login(Request $request)
    {
        $validator = Validator::make(
            $request->all(),
            [
                "email"             =>          "required|email",
                "password"          =>          "required"
            ]
        );
        if ($validator->fails()) {
            return response()->json(["status" => "failed", "validation_error" => $validator->errors()]);
        }
        $email_status = User::where("email", $request->email)->first();
        if (!is_null($email_status)) {
            if (Hash::check($request->password, $email_status->password)) {
                $credentials = $request->only('email', 'password');
                if (Auth::attempt($credentials)) {
                    foreach ($this->getUser()->tokens as $token) {
                        $token->delete();
                    }
                    $token = $this->getUser()->createToken('api-user-token');

                    return response()->json(["status" => 200, "success" => true, "message" => "You have logged in successfully", "data" => $token->plainTextToken]);
                }
            } else {
                return response()->json(["status" => "failed", "success" => false, "message" => "Unable to login. Incorrect credentials."])->setStatusCode(401);
            }
        } else {
            return response()->json(["status" => "failed", "success" => false, "message" => "Unable to login. Incorrect credentials."])->setStatusCode(401);
        }
    }

    public function register(Request $request)
    {
        $validator = Validator::make(
            $request->all(),
            [
                'email' => ['required', 'string', 'email', 'max:255'], // , 'unique:users'
                'password' => ['required', 'string', 'min:4'],
            ]
        );
        if ($validator->fails()) {
            return response()->json(["status" => "failed", "message" => "Please Input Valid Data", "errors" => $validator->errors()]);
        }
        $user_status = User::where("email", $request->email)->first();
        if (!is_null($user_status)) {
            return response()->json(["status" => "failed", "success" => false, "message" => "Whoops! email already registered"]);
        }

        $user = new User();
        $user->email = $request->post('email');
        $user->password = $request->post('password');
        $user->save();
        $token = $user->createToken('api-user-token');

        if (!is_null($user)) {
            Auth::guard()->login($user);
            return response()->json(["status" => 200, "success" => true, "message" => "Registration completed successfully", "data" => [$user, $token]]);
        } else {
            return response()->json(["status" => "failed", "success" => false, "message" => "Failed to register"]);
        }
    }

    private function getUser()
    {
        return Auth::user();
    }
}
