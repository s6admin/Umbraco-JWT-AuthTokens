﻿using System;
using Umbraco.Core.Persistence;
using Umbraco.Core.Persistence.DatabaseAnnotations;

namespace UmbracoAuthTokens.Data
{
    [TableName("identityAuthTokens")]
    [PrimaryKey("pk")]
    [ExplicitColumns]
    public class UmbracoAuthToken
    {
        [Column("pk")]
        [PrimaryKeyColumn]
        public int PrimaryKey { get; set; }

        [Column("identityId")]
        public int IdentityId { get; set; }

        [Column("identityType")]
        public string IdentityType { get; set; }

        [Column("dateCreated")]
        public DateTime DateCreated { get; set; }

        [Column("authToken")]
        public string AuthToken { get; set; }

		// S6 Added to match warren repo which tracks expiration
		[Column("dateExpires")]
		public DateTime DateExpires { get; set; }
	}
}
