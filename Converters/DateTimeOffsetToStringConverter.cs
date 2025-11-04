using System;
using System.Globalization;
using Microsoft.UI.Xaml.Data;

namespace Intelicense.Converters;

public sealed class DateTimeOffsetToStringConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is null)
        {
            return string.Empty;
        }

        var format = parameter as string;

        return value switch
        {
            DateTimeOffset dto => dto.ToString(format, CultureInfo.CurrentCulture),
            DateTime dt => dt.ToString(format, CultureInfo.CurrentCulture),
            _ => System.Convert.ToString(value, CultureInfo.CurrentCulture) ?? string.Empty
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language) => throw new NotSupportedException();
}
