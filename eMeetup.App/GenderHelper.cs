using eMeetup.App.Models;
using Microsoft.AspNetCore.Components;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace eMeetup.App;

public static class GenderHelper
{
    public static string GetDisplayName(Gender gender)
    {
        return gender switch
        {
            Gender.Male => "Male",
            Gender.Female => "Female",
            Gender.Other => "Other",
            Gender.PreferNotToSay => "Prefer not to say",
            _ => "Unknown"
        };
    }

    public static string GetIcon(Gender gender)
    {
        return gender switch
        {
            Gender.Male => "♂",
            Gender.Female => "♀",
            Gender.Other => "⚧",
            Gender.PreferNotToSay => "?",
            _ => "?"
        };
    }

    public static Dictionary<Gender, string> GetOptions()
    {
        return new Dictionary<Gender, string>
        {
            { Gender.Male, GetDisplayName(Gender.Male) },
            { Gender.Female, GetDisplayName(Gender.Female) },
            { Gender.Other, GetDisplayName(Gender.Other) },
            { Gender.PreferNotToSay, GetDisplayName(Gender.PreferNotToSay) }
        };
    }
}
