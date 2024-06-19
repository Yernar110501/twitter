package twitter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegisterInput_Sanitize(t *testing.T) {
	input := RegisterInput{
		Email:           "BOB@gmail.com",
		Username:        "  bob   ",
		Password:        "password",
		ConfirmPassword: "password",
	}

	want := RegisterInput{
		Email:           "bob@gmail.com",
		Username:        "bob",
		Password:        "password",
		ConfirmPassword: "password",
	}

	input.Sanitize()

	require.Equal(t, want, input)
}

func TestRegisterInput_Validate(t *testing.T) {
	testCases := []struct {
		name  string
		input RegisterInput
		err   error
	}{
		{
			name: "valid input",
			input: RegisterInput{
				Email:           "bob@gmail.com",
				Username:        "bob",
				Password:        "password",
				ConfirmPassword: "password",
			},
			err: nil,
		},
		{
			name: "invalid email",
			input: RegisterInput{
				Email:           "bob",
				Username:        "bob",
				Password:        "password",
				ConfirmPassword: "password",
			},
			err: ErrValidation,
		},
		{
			name: "too short username",
			input: RegisterInput{
				Email:           "bob@gmail.com",
				Username:        "b",
				Password:        "password",
				ConfirmPassword: "password",
			},
			err: ErrValidation,
		},
		{
			name: "too short password",
			input: RegisterInput{
				Email:           "bob@gmail.com",
				Username:        "bob",
				Password:        "pass",
				ConfirmPassword: "pass",
			},
			err: ErrValidation,
		},
		{
			name: "confirm password doesnt match password",
			input: RegisterInput{
				Email:           "bob@gmail.com",
				Username:        "bob",
				Password:        "password",
				ConfirmPassword: "password123",
			},
			err: ErrValidation,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.Validate()

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
