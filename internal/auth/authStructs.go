package auth

// login
type HasuraLoginPayload struct {
	Input struct {
		Credential LoginRequest `json:"credential"`
	} `json:"input"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type HasuraRefreshPayload struct {
	Input RefreshRequest `json:"input"`
}
type RefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// signup
type HasuraSignUpPayload struct {
	Input struct {
		Credential SignupInput `json:"credential"`
	} `json:"input"`
}

type SignupInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
