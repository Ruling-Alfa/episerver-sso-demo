﻿namespace Website.Models.Pages
{
    using System.ComponentModel.DataAnnotations;
    using EPiServer.Core;
    using EPiServer.DataAbstraction;
    using EPiServer.DataAnnotations;

    /// <summary>
    /// Used for the site's start page and also acts as a container for site settings
    /// </summary>
    [ContentType(GUID = "19671657-B684-4D95-A61F-8DD4FE60D559")]
    public class StartPage : PageData
    {
        [Display(GroupName = SystemTabNames.Content)]
        [CultureSpecific]
        public virtual ContentArea MainContentArea { get; set; }
    }
}