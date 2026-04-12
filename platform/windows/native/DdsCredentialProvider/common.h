// DDS Credential Provider — tile field layout.
// Forked from Crayonic CP; smart card fields stripped.

#pragma once
#include <helpers.h>

// The indexes of each of the fields in our credential provider's tiles.
enum SAMPLE_FIELD_ID
{
    SFI_TILEIMAGE         = 0,
    SFI_USERNAME          = 1,
    SFI_USERNAME_INFO     = 2,
    SFI_NUM_FIELDS_NO_USER = 3,

    SFI_SUBMIT_BUTTON     = 3,
    SFI_NUM_FIELDS        = 4,
};

struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SFI_TILEIMAGE
    { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SFI_USERNAME
    { CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },                   // SFI_USERNAME_INFO
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },          // SFI_SUBMIT_BUTTON
};

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE,     CPFT_TILE_IMAGE,    const_cast<LPWSTR>(L"Image_")        },
    { SFI_USERNAME,      CPFT_LARGE_TEXT,     const_cast<LPWSTR>(L"Username")      },
    { SFI_USERNAME_INFO, CPFT_SMALL_TEXT,     const_cast<LPWSTR>(L"Username Info")  },
    { SFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, const_cast<LPWSTR>(L"Submit")        },
};
