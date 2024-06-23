package domain

import (
	"context"
	"errors"
	"fmt"

	"github.com/Yernar110501/twitter"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	UserRepo twitter.UserRepo
}

func NewAuthService(ur twitter.UserRepo) *AuthService {
	return &AuthService{
		UserRepo: ur,
	}
}
func (as *AuthService) Register(ctx context.Context, input twitter.RegisterInput) (twitter.AuthResponse, error) {
	input.Sanitize()

	if err := input.Validate(); err != nil {
		return twitter.AuthResponse{}, err
	}

	if _, err := as.UserRepo.GetByUsername(ctx, input.Username); !errors.Is(err, twitter.ErrNotFound) {
		return twitter.AuthResponse{}, twitter.ErrUserNameTaken
	}

	if _, err := as.UserRepo.GetByEmail(ctx, input.Email); !errors.Is(err, twitter.ErrNotFound) {
		return twitter.AuthResponse{}, twitter.ErrEmailTaken
	}

	user := twitter.User{
		Email:    input.Email,
		Username: input.Username,
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return twitter.AuthResponse{}, fmt.Errorf("error hashing password %v", err)
	}
	user.Password = string(hashPassword)

	user, err = as.UserRepo.Create(ctx, user)

	if err != nil {
		return twitter.AuthResponse{}, fmt.Errorf("error creating user: %v", err)
	}
	return twitter.AuthResponse{
		AccessToken: "tokeen",
		User:        user,
	}, nil
}

func (as *AuthService) Loging(ctx context.Context, input twitter.LoginInput) (twitter.AuthResponse, error) {
	input.Sanitize()

	if err := input.Validate(); err != nil {
		return twitter.AuthResponse{}, err
	}
	user, err := as.UserRepo.GetByEmail(ctx, input.Email)
	if err != nil {
		switch {
		case errors.Is(err, twitter.ErrNotFound):
			return twitter.AuthResponse{}, twitter.ErrBadCredentials
		default:
			return twitter.AuthResponse{}, err
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return twitter.AuthResponse{}, twitter.ErrBadCredentials
	}
	return twitter.AuthResponse{
		AccessToken: "tokeen",
		User:        user,
	}, nil
}
